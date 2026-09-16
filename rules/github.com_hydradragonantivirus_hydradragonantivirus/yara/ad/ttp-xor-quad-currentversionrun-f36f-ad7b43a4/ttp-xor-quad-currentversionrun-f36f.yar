rule TTP_XOR_QUAD_CurrentVersionRun_f36f {
  strings:
    $key_f36f = { a0 00 [2] 84 0e [2] af 22 [2] 81 00 [2] 95 1b [2] 9a 01 [2] 84 1c [2] 86 1d [2] 9d 1b [2] 81 1c [2] 9d 33 }

  condition:
    any of them
}