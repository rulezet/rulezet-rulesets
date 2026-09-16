rule sig_20160823_21dbf5aa9896daf36f9e601c9c62e775 {
  meta:
    description = "datamaliciousorder - file 20160823_21dbf5aa9896daf36f9e601c9c62e775.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a0ca188317ca254d5beb280db01b863095f3c2b855d5bb1aa3fe199a5f00dcf"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}