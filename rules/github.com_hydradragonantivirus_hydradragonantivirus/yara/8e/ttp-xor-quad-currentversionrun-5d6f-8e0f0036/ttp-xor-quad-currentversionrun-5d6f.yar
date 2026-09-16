rule TTP_XOR_QUAD_CurrentVersionRun_5d6f {
  strings:
    $key_5d6f = { 0e 00 [2] 2a 0e [2] 01 22 [2] 2f 00 [2] 3b 1b [2] 34 01 [2] 2a 1c [2] 28 1d [2] 33 1b [2] 2f 1c [2] 33 33 }

  condition:
    any of them
}