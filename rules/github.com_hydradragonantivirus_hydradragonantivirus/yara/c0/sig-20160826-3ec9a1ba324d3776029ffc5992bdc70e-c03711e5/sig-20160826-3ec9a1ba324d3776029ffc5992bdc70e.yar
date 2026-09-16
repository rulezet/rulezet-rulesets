rule sig_20160826_3ec9a1ba324d3776029ffc5992bdc70e {
  meta:
    description = "datamaliciousorder - file 20160826_3ec9a1ba324d3776029ffc5992bdc70e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "238518fc2d28c3b8fbf4707d1447771844b4ecb2bc6078089f241c2416dea3ae"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}