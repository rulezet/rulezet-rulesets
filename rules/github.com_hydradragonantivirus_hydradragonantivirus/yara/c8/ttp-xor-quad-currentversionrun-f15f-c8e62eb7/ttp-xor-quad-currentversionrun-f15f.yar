rule TTP_XOR_QUAD_CurrentVersionRun_f15f {
  strings:
    $key_f15f = { a2 30 [2] 86 3e [2] ad 12 [2] 83 30 [2] 97 2b [2] 98 31 [2] 86 2c [2] 84 2d [2] 9f 2b [2] 83 2c [2] 9f 03 }

  condition:
    any of them
}