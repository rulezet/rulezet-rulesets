rule sig_20160824_f12916cf058aea5673f7542405a0353c {
  meta:
    description = "datamaliciousorder - file 20160824_f12916cf058aea5673f7542405a0353c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38ce7f9862bd3133189d7e4c439825aeff066dc22f5446bc0e07fb0e72788512"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}