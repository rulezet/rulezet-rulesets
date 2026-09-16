rule TTP_XOR_QUAD_CurrentVersionRun_49d2 {
  strings:
    $key_49d2 = { 1a bd [2] 3e b3 [2] 15 9f [2] 3b bd [2] 2f a6 [2] 20 bc [2] 3e a1 [2] 3c a0 [2] 27 a6 [2] 3b a1 [2] 27 8e }

  condition:
    any of them
}