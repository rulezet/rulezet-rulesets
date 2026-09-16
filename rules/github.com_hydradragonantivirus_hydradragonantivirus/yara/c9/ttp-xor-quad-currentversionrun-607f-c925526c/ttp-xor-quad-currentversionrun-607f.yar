rule TTP_XOR_QUAD_CurrentVersionRun_607f {
  strings:
    $key_607f = { 33 10 [2] 17 1e [2] 3c 32 [2] 12 10 [2] 06 0b [2] 09 11 [2] 17 0c [2] 15 0d [2] 0e 0b [2] 12 0c [2] 0e 23 }

  condition:
    any of them
}