rule TTP_XOR_QUAD_CurrentVersionRun_2f6f {
  strings:
    $key_2f6f = { 7c 00 [2] 58 0e [2] 73 22 [2] 5d 00 [2] 49 1b [2] 46 01 [2] 58 1c [2] 5a 1d [2] 41 1b [2] 5d 1c [2] 41 33 }

  condition:
    any of them
}