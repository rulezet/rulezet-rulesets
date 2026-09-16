rule TTP_XOR_QUAD_CurrentVersionRun_29d0 {
  strings:
    $key_29d0 = { 7a bf [2] 5e b1 [2] 75 9d [2] 5b bf [2] 4f a4 [2] 40 be [2] 5e a3 [2] 5c a2 [2] 47 a4 [2] 5b a3 [2] 47 8c }

  condition:
    any of them
}