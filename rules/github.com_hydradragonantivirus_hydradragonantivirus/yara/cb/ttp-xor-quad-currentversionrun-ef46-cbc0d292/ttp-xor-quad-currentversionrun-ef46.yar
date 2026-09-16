rule TTP_XOR_QUAD_CurrentVersionRun_ef46 {
  strings:
    $key_ef46 = { bc 29 [2] 98 27 [2] b3 0b [2] 9d 29 [2] 89 32 [2] 86 28 [2] 98 35 [2] 9a 34 [2] 81 32 [2] 9d 35 [2] 81 1a }

  condition:
    any of them
}