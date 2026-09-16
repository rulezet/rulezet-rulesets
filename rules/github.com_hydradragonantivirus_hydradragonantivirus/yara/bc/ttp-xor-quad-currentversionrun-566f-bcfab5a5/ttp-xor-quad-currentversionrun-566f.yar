rule TTP_XOR_QUAD_CurrentVersionRun_566f {
  strings:
    $key_566f = { 05 00 [2] 21 0e [2] 0a 22 [2] 24 00 [2] 30 1b [2] 3f 01 [2] 21 1c [2] 23 1d [2] 38 1b [2] 24 1c [2] 38 33 }

  condition:
    any of them
}