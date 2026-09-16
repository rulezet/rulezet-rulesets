rule TTP_XOR_QUAD_CurrentVersionRun_445f {
  strings:
    $key_445f = { 17 30 [2] 33 3e [2] 18 12 [2] 36 30 [2] 22 2b [2] 2d 31 [2] 33 2c [2] 31 2d [2] 2a 2b [2] 36 2c [2] 2a 03 }

  condition:
    any of them
}