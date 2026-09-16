rule sig_20160523_8e39e784a783908fb425dee86b2b13fc {
  meta:
    description = "datamaliciousorder - file 20160523_8e39e784a783908fb425dee86b2b13fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f99662d6dabd5f89b3630050628ac8e5a94f58a5004b38885f5aa3408d796a58"

  strings:
    $s1 = "split('').reverse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}