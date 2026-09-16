rule TTP_XOR_QUAD_CurrentVersionRun_3a6f {
  strings:
    $key_3a6f = { 69 00 [2] 4d 0e [2] 66 22 [2] 48 00 [2] 5c 1b [2] 53 01 [2] 4d 1c [2] 4f 1d [2] 54 1b [2] 48 1c [2] 54 33 }

  condition:
    any of them
}