rule TTP_XOR_QUAD_CurrentVersionRun_49d0 {
  strings:
    $key_49d0 = { 1a bf [2] 3e b1 [2] 15 9d [2] 3b bf [2] 2f a4 [2] 20 be [2] 3e a3 [2] 3c a2 [2] 27 a4 [2] 3b a3 [2] 27 8c }

  condition:
    any of them
}