rule TTP_XOR_QUAD_CurrentVersionRun_f14d {
  strings:
    $key_f14d = { a2 22 [2] 86 2c [2] ad 00 [2] 83 22 [2] 97 39 [2] 98 23 [2] 86 3e [2] 84 3f [2] 9f 39 [2] 83 3e [2] 9f 11 }

  condition:
    any of them
}