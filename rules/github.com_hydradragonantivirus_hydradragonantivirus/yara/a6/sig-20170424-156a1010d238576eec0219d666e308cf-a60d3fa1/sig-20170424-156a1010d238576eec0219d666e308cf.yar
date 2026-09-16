rule sig_20170424_156a1010d238576eec0219d666e308cf {
  meta:
    description = "datamaliciousorder - file 20170424_156a1010d238576eec0219d666e308cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c047f91ba3715d458a33362b6bb0985c7ed970fb5f66968b9012b53f0ab8606d"

  strings:
    $s1 = "if (yCNxOKcTfEXIhLYz.FolderExists(\"C:\\\\w\"+\"InD\"+\"oWS\") == true) {" fullword ascii
    $s2 = "function pYtoUXkLzcgeVHmq(pamsQKFNfzyRPiJX, SdpyAgjBOosYbtuael, JNqHEXmoOWFRzYhbcC) { " fullword ascii
    $s3 = "return pamsQKFNfzyRPiJX.split(SdpyAgjBOosYbtuael).join(JNqHEXmoOWFRzYhbcC); }" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}