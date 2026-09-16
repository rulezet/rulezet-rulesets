rule _20160921_ce3c0604d52e9dc9119cefedfee34385_20160921_eb8df0d94f3c_1929 {
  meta:
    description = "datamaliciousorder - from files 20160921_ce3c0604d52e9dc9119cefedfee34385.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"
    hash2       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1  = " fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"J" ascii
    $s2  = "\"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(func" ascii
    $s3  = " fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s4  = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Y" ascii
    $s5  = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s6  = " \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(func" ascii
    $s7  = ",(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){" ascii
    $s8  = "\"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"UOe\";})(),(fun" ascii
    $s9  = "})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(function fuc" ascii
    $s10 = "ck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"OPz" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}