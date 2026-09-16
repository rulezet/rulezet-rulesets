rule TTP_XOR_QUAD_CurrentVersionRun_7ad2 {
  strings:
    $key_7ad2 = { 29 bd [2] 0d b3 [2] 26 9f [2] 08 bd [2] 1c a6 [2] 13 bc [2] 0d a1 [2] 0f a0 [2] 14 a6 [2] 08 a1 [2] 14 8e }

  condition:
    any of them
}