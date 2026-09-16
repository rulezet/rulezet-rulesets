rule TTP_XOR_QUAD_CurrentVersionRun_f356 {
  strings:
    $key_f356 = { a0 39 [2] 84 37 [2] af 1b [2] 81 39 [2] 95 22 [2] 9a 38 [2] 84 25 [2] 86 24 [2] 9d 22 [2] 81 25 [2] 9d 0a }

  condition:
    any of them
}