rule sig_20160824_11082651df5ec26d45436404a1f5448f {
  meta:
    description = "datamaliciousorder - file 20160824_11082651df5ec26d45436404a1f5448f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf3dd0b189787882ac44f3b893e5f25187024a296c304f75736af1746bd20553"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}