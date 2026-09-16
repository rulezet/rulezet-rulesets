rule sig_20160826_db7dc4bc6866cd2ccc0d37a5c8cefada {
  meta:
    description = "datamaliciousorder - file 20160826_db7dc4bc6866cd2ccc0d37a5c8cefada.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b978e56ddd483d554d8a4691c4ff99995265cb29c9bab13abe3b3419f57a23f"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}