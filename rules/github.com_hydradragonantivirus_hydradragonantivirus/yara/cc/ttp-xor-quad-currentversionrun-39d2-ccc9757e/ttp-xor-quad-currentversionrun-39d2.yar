rule TTP_XOR_QUAD_CurrentVersionRun_39d2 {
  strings:
    $key_39d2 = { 6a bd [2] 4e b3 [2] 65 9f [2] 4b bd [2] 5f a6 [2] 50 bc [2] 4e a1 [2] 4c a0 [2] 57 a6 [2] 4b a1 [2] 57 8e }

  condition:
    any of them
}