rule TTP_XOR_QUAD_CurrentVersionRun_f362 {
  strings:
    $key_f362 = { a0 0d [2] 84 03 [2] af 2f [2] 81 0d [2] 95 16 [2] 9a 0c [2] 84 11 [2] 86 10 [2] 9d 16 [2] 81 11 [2] 9d 3e }

  condition:
    any of them
}