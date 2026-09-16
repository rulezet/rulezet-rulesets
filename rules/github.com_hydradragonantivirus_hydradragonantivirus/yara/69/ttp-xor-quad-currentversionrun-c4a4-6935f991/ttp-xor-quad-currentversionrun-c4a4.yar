rule TTP_XOR_QUAD_CurrentVersionRun_c4a4 {
  strings:
    $key_c4a4 = { 97 cb [2] b3 c5 [2] 98 e9 [2] b6 cb [2] a2 d0 [2] ad ca [2] b3 d7 [2] b1 d6 [2] aa d0 [2] b6 d7 [2] aa f8 }

  condition:
    any of them
}