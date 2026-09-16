rule TTP_XOR_QUAD_CurrentVersionRun_537f {
  strings:
    $key_537f = { 00 10 [2] 24 1e [2] 0f 32 [2] 21 10 [2] 35 0b [2] 3a 11 [2] 24 0c [2] 26 0d [2] 3d 0b [2] 21 0c [2] 3d 23 }

  condition:
    any of them
}