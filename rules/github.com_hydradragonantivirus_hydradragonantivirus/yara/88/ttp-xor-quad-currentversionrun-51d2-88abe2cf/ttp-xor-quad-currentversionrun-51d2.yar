rule TTP_XOR_QUAD_CurrentVersionRun_51d2 {
  strings:
    $key_51d2 = { 02 bd [2] 26 b3 [2] 0d 9f [2] 23 bd [2] 37 a6 [2] 38 bc [2] 26 a1 [2] 24 a0 [2] 3f a6 [2] 23 a1 [2] 3f 8e }

  condition:
    any of them
}