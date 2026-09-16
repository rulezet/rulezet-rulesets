rule TTP_XOR_QUAD_CurrentVersionRun_507f {
  strings:
    $key_507f = { 03 10 [2] 27 1e [2] 0c 32 [2] 22 10 [2] 36 0b [2] 39 11 [2] 27 0c [2] 25 0d [2] 3e 0b [2] 22 0c [2] 3e 23 }

  condition:
    any of them
}