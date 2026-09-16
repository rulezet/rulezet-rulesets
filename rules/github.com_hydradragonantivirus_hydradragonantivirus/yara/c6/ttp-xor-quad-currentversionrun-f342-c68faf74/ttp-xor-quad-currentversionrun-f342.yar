rule TTP_XOR_QUAD_CurrentVersionRun_f342 {
  strings:
    $key_f342 = { a0 2d [2] 84 23 [2] af 0f [2] 81 2d [2] 95 36 [2] 9a 2c [2] 84 31 [2] 86 30 [2] 9d 36 [2] 81 31 [2] 9d 1e }

  condition:
    any of them
}