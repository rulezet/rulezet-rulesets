rule TTP_XOR_QUAD_CurrentVersionRun_f66f {
  strings:
    $key_f66f = { a5 00 [2] 81 0e [2] aa 22 [2] 84 00 [2] 90 1b [2] 9f 01 [2] 81 1c [2] 83 1d [2] 98 1b [2] 84 1c [2] 98 33 }

  condition:
    any of them
}