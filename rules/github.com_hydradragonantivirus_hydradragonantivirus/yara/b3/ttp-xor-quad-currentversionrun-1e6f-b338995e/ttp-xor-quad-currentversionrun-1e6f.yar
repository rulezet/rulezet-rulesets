rule TTP_XOR_QUAD_CurrentVersionRun_1e6f {
  strings:
    $key_1e6f = { 4d 00 [2] 69 0e [2] 42 22 [2] 6c 00 [2] 78 1b [2] 77 01 [2] 69 1c [2] 6b 1d [2] 70 1b [2] 6c 1c [2] 70 33 }

  condition:
    any of them
}