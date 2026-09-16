rule TTP_XOR_QUAD_CurrentVersionRun_6c6f {
  strings:
    $key_6c6f = { 3f 00 [2] 1b 0e [2] 30 22 [2] 1e 00 [2] 0a 1b [2] 05 01 [2] 1b 1c [2] 19 1d [2] 02 1b [2] 1e 1c [2] 02 33 }

  condition:
    any of them
}