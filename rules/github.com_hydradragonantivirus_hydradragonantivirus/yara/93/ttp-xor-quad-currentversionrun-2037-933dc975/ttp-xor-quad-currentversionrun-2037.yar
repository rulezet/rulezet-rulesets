rule TTP_XOR_QUAD_CurrentVersionRun_2037 {
  strings:
    $key_2037 = { 73 58 [2] 57 56 [2] 7c 7a [2] 52 58 [2] 46 43 [2] 49 59 [2] 57 44 [2] 55 45 [2] 4e 43 [2] 52 44 [2] 4e 6b }

  condition:
    any of them
}