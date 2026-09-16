rule TTP_XOR_QUAD_CurrentVersionRun_76a4 {
  strings:
    $key_76a4 = { 25 cb [2] 01 c5 [2] 2a e9 [2] 04 cb [2] 10 d0 [2] 1f ca [2] 01 d7 [2] 03 d6 [2] 18 d0 [2] 04 d7 [2] 18 f8 }

  condition:
    any of them
}