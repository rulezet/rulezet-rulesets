rule Trojan_Autorun_Generic_Ransom_GandCrab_CD282962 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Ransom.GandCrab.CD282962.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdf96eb2167219781114c8334719cdbd5d0df5d09d43ea23932f2629e5734f5d"

  strings:
    $s1  = "1. Download Tor browser - https://www.torproject.org/ " fullword wide
    $s2  = "Fatal error: rsaenh.dll is not initialized as well" fullword ascii
    $s3  = "Do not try to modify files or use your own private key - this will result in the loss of your data forever! " fullword wide
    $s4  = "On our page you will see instructions on payment and get the opportunity to decrypt 1 file for free. " fullword wide
    $s5  = "1. Visit https://tox.chat/download.html" fullword wide
    $s6  = "All your files documents, photos, databases and other important files are encrypted and have the extension: .GDCB " fullword wide
    $s7  = "4. Search our contact - 6C5AD4057E594E090E0C987B3089F74335DA75F04B7403E0575663C261349569F64D28CDCF45" fullword wide
    $s8  = "The server with your key is in a closed network TOR. You can get there by the following ways: " fullword wide
    $s9  = "2. Download and install qTOX on your PC." fullword wide
    $s10 = "If you can't download TOR and use it, or in your country TOR blocked, read it:" fullword wide
    $s11 = "The only method of recovering files is to purchase a private key. It is on our server and only we can recover your files. " fullword wide
    $s12 = "DELETE}" fullword ascii
    $s13 = "Attention! " fullword wide
    $s14 = "2. Install Tor browser " fullword wide
    $s15 = "3. Open Tor Browser " fullword wide
    $s16 = "5. Follow the instructions on this page " fullword wide
    $s17 = "3. Open it, click \"New Profile\" and create profile." fullword wide
    $s18 = "DANGEROUS! " fullword wide
    $s19 = "m cannot be run in DOS mode." fullword ascii
    $s20 = "4. Open link in tor browser: http://gdcbghvjyqy7jclk.onion/3a23db8448d3b2b                         " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}