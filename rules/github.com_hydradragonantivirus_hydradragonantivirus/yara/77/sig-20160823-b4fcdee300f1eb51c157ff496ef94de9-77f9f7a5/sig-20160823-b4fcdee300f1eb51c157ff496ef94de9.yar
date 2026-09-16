rule sig_20160823_b4fcdee300f1eb51c157ff496ef94de9 {
  meta:
    description = "datamaliciousorder - file 20160823_b4fcdee300f1eb51c157ff496ef94de9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0293d24eba8e5cfdbaedc8f798a73e1e117d0d70d27d02a00594f87139bad779"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}