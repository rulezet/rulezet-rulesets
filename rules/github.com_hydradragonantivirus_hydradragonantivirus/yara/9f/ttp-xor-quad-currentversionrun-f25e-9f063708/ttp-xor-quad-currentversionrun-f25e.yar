rule TTP_XOR_QUAD_CurrentVersionRun_f25e {
  strings:
    $key_f25e = { a1 31 [2] 85 3f [2] ae 13 [2] 80 31 [2] 94 2a [2] 9b 30 [2] 85 2d [2] 87 2c [2] 9c 2a [2] 80 2d [2] 9c 02 }

  condition:
    any of them
}