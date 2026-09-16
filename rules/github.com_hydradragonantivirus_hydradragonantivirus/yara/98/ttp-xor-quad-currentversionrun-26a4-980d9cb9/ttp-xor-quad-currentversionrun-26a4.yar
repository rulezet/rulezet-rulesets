rule TTP_XOR_QUAD_CurrentVersionRun_26a4 {
  strings:
    $key_26a4 = { 75 cb [2] 51 c5 [2] 7a e9 [2] 54 cb [2] 40 d0 [2] 4f ca [2] 51 d7 [2] 53 d6 [2] 48 d0 [2] 54 d7 [2] 48 f8 }

  condition:
    any of them
}