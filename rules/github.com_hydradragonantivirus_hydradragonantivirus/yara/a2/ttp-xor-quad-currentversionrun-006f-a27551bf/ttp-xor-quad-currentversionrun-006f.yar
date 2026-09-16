rule TTP_XOR_QUAD_CurrentVersionRun_006f {
  strings:
    $key_006f = { 53 00 [2] 77 0e [2] 5c 22 [2] 72 00 [2] 66 1b [2] 69 01 [2] 77 1c [2] 75 1d [2] 6e 1b [2] 72 1c [2] 6e 33 }

  condition:
    any of them
}