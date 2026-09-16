rule TTP_XOR_QUAD_CurrentVersionRun_18d2 {
  strings:
    $key_18d2 = { 4b bd [2] 6f b3 [2] 44 9f [2] 6a bd [2] 7e a6 [2] 71 bc [2] 6f a1 [2] 6d a0 [2] 76 a6 [2] 6a a1 [2] 76 8e }

  condition:
    any of them
}