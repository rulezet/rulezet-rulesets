rule TTP_XOR_QUAD_CurrentVersionRun_5dd0 {
  strings:
    $key_5dd0 = { 0e bf [2] 2a b1 [2] 01 9d [2] 2f bf [2] 3b a4 [2] 34 be [2] 2a a3 [2] 28 a2 [2] 33 a4 [2] 2f a3 [2] 33 8c }

  condition:
    any of them
}