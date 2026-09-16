rule TTP_XOR_QUAD_CurrentVersionRun_1ad2 {
  strings:
    $key_1ad2 = { 49 bd [2] 6d b3 [2] 46 9f [2] 68 bd [2] 7c a6 [2] 73 bc [2] 6d a1 [2] 6f a0 [2] 74 a6 [2] 68 a1 [2] 74 8e }

  condition:
    any of them
}