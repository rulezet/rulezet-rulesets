rule sig_20160525_14f98f869b861ff870753c4b3b373971 {
  meta:
    description = "datamaliciousorder - file 20160525_14f98f869b861ff870753c4b3b373971.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6befa3a4d82e8bb849435418998e6d4027a73015c851a2d8430c75a230817e23"

  strings:
    $s1 = "neth rav\\n;\"P46x\\\\\" = ssorcah rav\\n;\"eSKe6x\\\\\" = tsilslianbmuhtoh rav\\n;\"45x\\\\G\" = cthh rav\\n;\"ee2x\\\\\" = rer" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}