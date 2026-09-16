rule TTP_XOR_QUAD_CurrentVersionRun_235f {
  strings:
    $key_235f = { 70 30 [2] 54 3e [2] 7f 12 [2] 51 30 [2] 45 2b [2] 4a 31 [2] 54 2c [2] 56 2d [2] 4d 2b [2] 51 2c [2] 4d 03 }

  condition:
    any of them
}