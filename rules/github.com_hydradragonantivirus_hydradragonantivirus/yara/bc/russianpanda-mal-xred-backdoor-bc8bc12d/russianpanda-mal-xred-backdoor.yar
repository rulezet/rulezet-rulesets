rule RUSSIANPANDA_Mal_Xred_Backdoor: FILE {
  meta:
    description = "Detects XRed backdoor"
    author      = "RussianPanda"
    id          = "61f5fcb8-9351-5db0-8bce-123c96d2a443"
    date        = "2024-02-09"
    modified    = "2024-02-09"
    reference   = "https://github.com/RussianPanda95/Yara-Rules"
    source_url  = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/XRed_Backdoor/mal_xred_backdoor.yar#L1-L18"
    license_url = "N/A"
    hash        = "9e1fbae3a659899dde8db18a32daa46a"
    logic_hash  = "36d138a0efade1d5c075662dc528235fe66b49879730db78c4c7290fec7420b5"
    score       = 75
    quality     = 73
    tags        = "FILE"

  strings:
    $s1 = "Keyboard Hook -> Active"
    $s2 = "TCP Client -> Aktif"
    $s3 = "USB Hooks -> Active"
    $s4 = "EXEURL1"
    $s5 = "INIURL3"
    $s6 = "XRed57"

  condition:
    uint16(0) == 0x5A4D and 3 of them
}