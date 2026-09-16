rule TTP_XOR_QUAD_CurrentVersionRun_2ed0 {
  strings:
    $key_2ed0 = { 7d bf [2] 59 b1 [2] 72 9d [2] 5c bf [2] 48 a4 [2] 47 be [2] 59 a3 [2] 5b a2 [2] 40 a4 [2] 5c a3 [2] 40 8c }

  condition:
    any of them
}