rule TTP_XOR_QUAD_CurrentVersionRun_f346 {
  strings:
    $key_f346 = { a0 29 [2] 84 27 [2] af 0b [2] 81 29 [2] 95 32 [2] 9a 28 [2] 84 35 [2] 86 34 [2] 9d 32 [2] 81 35 [2] 9d 1a }

  condition:
    any of them
}