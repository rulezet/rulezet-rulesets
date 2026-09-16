rule TTP_XOR_QUAD_CurrentVersionRun_7cd0 {
  strings:
    $key_7cd0 = { 2f bf [2] 0b b1 [2] 20 9d [2] 0e bf [2] 1a a4 [2] 15 be [2] 0b a3 [2] 09 a2 [2] 12 a4 [2] 0e a3 [2] 12 8c }

  condition:
    any of them
}