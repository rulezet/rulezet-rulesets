rule TTP_XOR_QUAD_CurrentVersionRun_5f7f {
  strings:
    $key_5f7f = { 0c 10 [2] 28 1e [2] 03 32 [2] 2d 10 [2] 39 0b [2] 36 11 [2] 28 0c [2] 2a 0d [2] 31 0b [2] 2d 0c [2] 31 23 }

  condition:
    any of them
}