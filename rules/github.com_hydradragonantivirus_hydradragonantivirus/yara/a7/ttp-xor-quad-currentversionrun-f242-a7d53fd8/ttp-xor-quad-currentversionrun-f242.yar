rule TTP_XOR_QUAD_CurrentVersionRun_f242 {
  strings:
    $key_f242 = { a1 2d [2] 85 23 [2] ae 0f [2] 80 2d [2] 94 36 [2] 9b 2c [2] 85 31 [2] 87 30 [2] 9c 36 [2] 80 31 [2] 9c 1e }

  condition:
    any of them
}