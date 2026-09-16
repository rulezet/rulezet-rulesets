rule TTP_XOR_QUAD_CurrentVersionRun_3cd0 {
  strings:
    $key_3cd0 = { 6f bf [2] 4b b1 [2] 60 9d [2] 4e bf [2] 5a a4 [2] 55 be [2] 4b a3 [2] 49 a2 [2] 52 a4 [2] 4e a3 [2] 52 8c }

  condition:
    any of them
}