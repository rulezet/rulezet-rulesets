rule TTP_XOR_QUAD_CurrentVersionRun_21a4 {
  strings:
    $key_21a4 = { 72 cb [2] 56 c5 [2] 7d e9 [2] 53 cb [2] 47 d0 [2] 48 ca [2] 56 d7 [2] 54 d6 [2] 4f d0 [2] 53 d7 [2] 4f f8 }

  condition:
    any of them
}