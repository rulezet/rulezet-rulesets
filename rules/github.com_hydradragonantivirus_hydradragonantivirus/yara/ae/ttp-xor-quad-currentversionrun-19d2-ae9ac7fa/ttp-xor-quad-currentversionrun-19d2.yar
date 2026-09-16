rule TTP_XOR_QUAD_CurrentVersionRun_19d2 {
  strings:
    $key_19d2 = { 4a bd [2] 6e b3 [2] 45 9f [2] 6b bd [2] 7f a6 [2] 70 bc [2] 6e a1 [2] 6c a0 [2] 77 a6 [2] 6b a1 [2] 77 8e }

  condition:
    any of them
}