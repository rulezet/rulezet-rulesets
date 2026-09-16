rule TTP_XOR_QUAD_CurrentVersionRun_276f {
  strings:
    $key_276f = { 74 00 [2] 50 0e [2] 7b 22 [2] 55 00 [2] 41 1b [2] 4e 01 [2] 50 1c [2] 52 1d [2] 49 1b [2] 55 1c [2] 49 33 }

  condition:
    any of them
}