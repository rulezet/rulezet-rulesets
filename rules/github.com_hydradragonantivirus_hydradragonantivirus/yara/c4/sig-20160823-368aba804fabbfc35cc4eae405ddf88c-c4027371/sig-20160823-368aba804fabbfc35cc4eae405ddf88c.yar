rule sig_20160823_368aba804fabbfc35cc4eae405ddf88c {
  meta:
    description = "datamaliciousorder - file 20160823_368aba804fabbfc35cc4eae405ddf88c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "786b4fd1efdcfd3dcd88afcc9db8ec4c314bd7e4dcb9ecee3d5a160d21efeaf7"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}