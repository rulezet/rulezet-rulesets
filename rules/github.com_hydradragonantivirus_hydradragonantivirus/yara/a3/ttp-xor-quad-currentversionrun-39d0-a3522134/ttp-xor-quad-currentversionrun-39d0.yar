rule TTP_XOR_QUAD_CurrentVersionRun_39d0 {
  strings:
    $key_39d0 = { 6a bf [2] 4e b1 [2] 65 9d [2] 4b bf [2] 5f a4 [2] 50 be [2] 4e a3 [2] 4c a2 [2] 57 a4 [2] 4b a3 [2] 57 8c }

  condition:
    any of them
}