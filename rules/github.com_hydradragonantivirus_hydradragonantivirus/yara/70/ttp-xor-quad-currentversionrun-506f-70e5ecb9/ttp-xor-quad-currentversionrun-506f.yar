rule TTP_XOR_QUAD_CurrentVersionRun_506f {
  strings:
    $key_506f = { 03 00 [2] 27 0e [2] 0c 22 [2] 22 00 [2] 36 1b [2] 39 01 [2] 27 1c [2] 25 1d [2] 3e 1b [2] 22 1c [2] 3e 33 }

  condition:
    any of them
}