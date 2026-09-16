rule TTP_XOR_QUAD_CurrentVersionRun_447f {
  strings:
    $key_447f = { 17 10 [2] 33 1e [2] 18 32 [2] 36 10 [2] 22 0b [2] 2d 11 [2] 33 0c [2] 31 0d [2] 2a 0b [2] 36 0c [2] 2a 23 }

  condition:
    any of them
}