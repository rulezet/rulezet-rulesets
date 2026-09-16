rule TTP_XOR_QUAD_CurrentVersionRun_f6a4 {
  strings:
    $key_f6a4 = { a5 cb [2] 81 c5 [2] aa e9 [2] 84 cb [2] 90 d0 [2] 9f ca [2] 81 d7 [2] 83 d6 [2] 98 d0 [2] 84 d7 [2] 98 f8 }

  condition:
    any of them
}