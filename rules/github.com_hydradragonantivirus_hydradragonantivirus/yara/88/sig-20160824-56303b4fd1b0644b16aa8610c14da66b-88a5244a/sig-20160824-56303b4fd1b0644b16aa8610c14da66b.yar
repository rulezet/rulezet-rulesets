rule sig_20160824_56303b4fd1b0644b16aa8610c14da66b {
  meta:
    description = "datamaliciousorder - file 20160824_56303b4fd1b0644b16aa8610c14da66b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76abf09a9e7cfe76e91e0b0255fc14fab0631425447d6a396dd0e31e62a8ebab"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}