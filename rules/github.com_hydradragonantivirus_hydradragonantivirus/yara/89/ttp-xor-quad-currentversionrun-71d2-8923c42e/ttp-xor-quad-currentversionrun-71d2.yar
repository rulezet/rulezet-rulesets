rule TTP_XOR_QUAD_CurrentVersionRun_71d2 {
  strings:
    $key_71d2 = { 22 bd [2] 06 b3 [2] 2d 9f [2] 03 bd [2] 17 a6 [2] 18 bc [2] 06 a1 [2] 04 a0 [2] 1f a6 [2] 03 a1 [2] 1f 8e }

  condition:
    any of them
}