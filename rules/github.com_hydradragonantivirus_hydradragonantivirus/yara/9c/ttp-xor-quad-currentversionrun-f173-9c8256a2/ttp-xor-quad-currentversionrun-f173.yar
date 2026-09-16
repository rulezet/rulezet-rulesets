rule TTP_XOR_QUAD_CurrentVersionRun_f173 {
  strings:
    $key_f173 = { a2 1c [2] 86 12 [2] ad 3e [2] 83 1c [2] 97 07 [2] 98 1d [2] 86 00 [2] 84 01 [2] 9f 07 [2] 83 00 [2] 9f 2f }

  condition:
    any of them
}