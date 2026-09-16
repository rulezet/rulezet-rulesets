rule TTP_XOR_QUAD_CurrentVersionRun_13b6 {
  strings:
    $key_13b6 = { 40 d9 [2] 64 d7 [2] 4f fb [2] 61 d9 [2] 75 c2 [2] 7a d8 [2] 64 c5 [2] 66 c4 [2] 7d c2 [2] 61 c5 [2] 7d ea }

  condition:
    any of them
}