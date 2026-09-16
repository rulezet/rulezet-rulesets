rule _20160921_5eea6af1c50b807f547cb710eb413110_20160922_41319625a334_5271 {
  meta:
    description = "datamaliciousorder - from files 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160922_41319625a3342333693d5eefb82a43ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash2       = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"

  strings:
    $s1 = "(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){re" ascii
    $s2 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s3 = "KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s4 = "n \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(fu" ascii
    $s5 = "(function f000(){return \"Nv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}