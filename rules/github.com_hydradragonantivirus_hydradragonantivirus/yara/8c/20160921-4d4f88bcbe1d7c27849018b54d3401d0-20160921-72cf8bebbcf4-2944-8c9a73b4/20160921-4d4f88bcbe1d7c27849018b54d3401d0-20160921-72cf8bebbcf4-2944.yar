rule _20160921_4d4f88bcbe1d7c27849018b54d3401d0_20160921_72cf8bebbcf4_2944 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash2       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"

  strings:
    $s1 = "nction f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Mc\";})(),(function f000(){retu" ascii
    $s2 = " f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"O" ascii
    $s3 = "Nv\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s4 = ",(function f000(){return \"Lo\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){" ascii
    $s5 = " \"MJq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(fun" ascii
    $s6 = "\"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Ml\";})(),(functi" ascii
    $s7 = "00(){return \"Km\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}