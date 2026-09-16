rule TTP_XOR_QUAD_CurrentVersionRun_3c6f {
  strings:
    $key_3c6f = { 6f 00 [2] 4b 0e [2] 60 22 [2] 4e 00 [2] 5a 1b [2] 55 01 [2] 4b 1c [2] 49 1d [2] 52 1b [2] 4e 1c [2] 52 33 }

  condition:
    any of them
}