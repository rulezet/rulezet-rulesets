rule MAL_AsyncRAT_Github_release {
  meta:
    description   = "Matches strings found in AsyncRAT Github release."
    last_modified = "2024-02-23"
    author        = "@petermstewart"
    DaysofYara    = "54/100"
    sha256        = "06899071233d61009a64c726a4523aa13d81c2517a0486cc99ac5931837008e5"
    ref           = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"

  strings:
    $a1 = "NYAN-x-CAT"
    $a2 = "This program is distributed for educational purposes only."
    $a3 = "namespace AsyncRAT"
    $b1 = "[!] If you wish to upgrade to new version of AsyncRAT, You will need to copy 'ServerCertificate.p12'." wide
    $b2 = "[!] If you lose\\delete 'ServerCertificate.p12' certificate you will NOT be able to control your clients, You will lose them all." wide
    $b3 = "AsyncRAT | Dot Net Editor" wide
    $b4 = "XMR Miner | AsyncRAT" wide
    $b5 = "SEND A NOTIFICATION WHEN CLIENT OPEN A SPECIFIC WINDOW" wide
    $b6 = "Popup UAC prompt?" wide
    $b7 = "AsyncRAT | Unistall" wide
    $b8 = "recovered passwords successfully @ ClientsFolder" wide

  condition:
    uint16(0) == 0x5a4d and
    all of ($a*) or
    6 of ($b*)
}