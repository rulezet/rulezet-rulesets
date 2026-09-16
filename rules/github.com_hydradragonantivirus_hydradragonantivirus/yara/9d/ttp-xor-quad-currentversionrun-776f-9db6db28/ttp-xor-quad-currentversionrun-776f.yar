rule TTP_XOR_QUAD_CurrentVersionRun_776f {
  strings:
    $key_776f = { 24 00 [2] 00 0e [2] 2b 22 [2] 05 00 [2] 11 1b [2] 1e 01 [2] 00 1c [2] 02 1d [2] 19 1b [2] 05 1c [2] 19 33 }

  condition:
    any of them
}