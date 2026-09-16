rule TTP_XOR_QUAD_CurrentVersionRun_f44d {
  strings:
    $key_f44d = { a7 22 [2] 83 2c [2] a8 00 [2] 86 22 [2] 92 39 [2] 9d 23 [2] 83 3e [2] 81 3f [2] 9a 39 [2] 86 3e [2] 9a 11 }

  condition:
    any of them
}