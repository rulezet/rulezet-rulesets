rule TTP_XOR_QUAD_CurrentVersionRun_52d1 {
  strings:
    $key_52d1 = { 01 be [2] 25 b0 [2] 0e 9c [2] 20 be [2] 34 a5 [2] 3b bf [2] 25 a2 [2] 27 a3 [2] 3c a5 [2] 20 a2 [2] 3c 8d }

  condition:
    any of them
}