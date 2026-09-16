rule TTP_XOR_QUAD_CurrentVersionRun_65d1 {
  strings:
    $key_65d1 = { 36 be [2] 12 b0 [2] 39 9c [2] 17 be [2] 03 a5 [2] 0c bf [2] 12 a2 [2] 10 a3 [2] 0b a5 [2] 17 a2 [2] 0b 8d }

  condition:
    any of them
}