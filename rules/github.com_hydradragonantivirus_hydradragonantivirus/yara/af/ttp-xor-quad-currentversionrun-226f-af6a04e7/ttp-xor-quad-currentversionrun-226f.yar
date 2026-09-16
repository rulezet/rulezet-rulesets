rule TTP_XOR_QUAD_CurrentVersionRun_226f {
  strings:
    $key_226f = { 71 00 [2] 55 0e [2] 7e 22 [2] 50 00 [2] 44 1b [2] 4b 01 [2] 55 1c [2] 57 1d [2] 4c 1b [2] 50 1c [2] 4c 33 }

  condition:
    any of them
}