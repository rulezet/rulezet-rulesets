rule TTP_XOR_QUAD_CurrentVersionRun_1b6f {
  strings:
    $key_1b6f = { 48 00 [2] 6c 0e [2] 47 22 [2] 69 00 [2] 7d 1b [2] 72 01 [2] 6c 1c [2] 6e 1d [2] 75 1b [2] 69 1c [2] 75 33 }

  condition:
    any of them
}