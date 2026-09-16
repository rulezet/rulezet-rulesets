rule TTP_XOR_QUAD_CurrentVersionRun_1a6f {
  strings:
    $key_1a6f = { 49 00 [2] 6d 0e [2] 46 22 [2] 68 00 [2] 7c 1b [2] 73 01 [2] 6d 1c [2] 6f 1d [2] 74 1b [2] 68 1c [2] 74 33 }

  condition:
    any of them
}