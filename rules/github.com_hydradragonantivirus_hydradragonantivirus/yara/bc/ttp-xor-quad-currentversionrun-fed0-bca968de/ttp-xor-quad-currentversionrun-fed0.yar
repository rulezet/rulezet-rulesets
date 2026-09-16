rule TTP_XOR_QUAD_CurrentVersionRun_fed0 {
  strings:
    $key_fed0 = { ad bf [2] 89 b1 [2] a2 9d [2] 8c bf [2] 98 a4 [2] 97 be [2] 89 a3 [2] 8b a2 [2] 90 a4 [2] 8c a3 [2] 90 8c }

  condition:
    any of them
}