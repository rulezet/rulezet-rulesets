rule TTP_XOR_QUAD_CurrentVersionRun_34a4 {
  strings:
    $key_34a4 = { 67 cb [2] 43 c5 [2] 68 e9 [2] 46 cb [2] 52 d0 [2] 5d ca [2] 43 d7 [2] 41 d6 [2] 5a d0 [2] 46 d7 [2] 5a f8 }

  condition:
    any of them
}