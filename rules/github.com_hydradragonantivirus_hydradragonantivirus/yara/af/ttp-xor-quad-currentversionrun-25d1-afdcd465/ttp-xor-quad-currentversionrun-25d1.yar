rule TTP_XOR_QUAD_CurrentVersionRun_25d1 {
  strings:
    $key_25d1 = { 76 be [2] 52 b0 [2] 79 9c [2] 57 be [2] 43 a5 [2] 4c bf [2] 52 a2 [2] 50 a3 [2] 4b a5 [2] 57 a2 [2] 4b 8d }

  condition:
    any of them
}