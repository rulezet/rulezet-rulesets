rule TTP_XOR_QUAD_CurrentVersionRun_516f {
  strings:
    $key_516f = { 02 00 [2] 26 0e [2] 0d 22 [2] 23 00 [2] 37 1b [2] 38 01 [2] 26 1c [2] 24 1d [2] 3f 1b [2] 23 1c [2] 3f 33 }

  condition:
    any of them
}