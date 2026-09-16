rule TTP_XOR_QUAD_CurrentVersionRun_f25f {
  strings:
    $key_f25f = { a1 30 [2] 85 3e [2] ae 12 [2] 80 30 [2] 94 2b [2] 9b 31 [2] 85 2c [2] 87 2d [2] 9c 2b [2] 80 2c [2] 9c 03 }

  condition:
    any of them
}