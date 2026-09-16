rule TTP_XOR_QUAD_CurrentVersionRun_bfd2 {
  strings:
    $key_bfd2 = { ec bd [2] c8 b3 [2] e3 9f [2] cd bd [2] d9 a6 [2] d6 bc [2] c8 a1 [2] ca a0 [2] d1 a6 [2] cd a1 [2] d1 8e }

  condition:
    any of them
}