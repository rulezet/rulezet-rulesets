rule TTP_XOR_QUAD_CurrentVersionRun_084d {
  strings:
    $key_084d = { 5b 22 [2] 7f 2c [2] 54 00 [2] 7a 22 [2] 6e 39 [2] 61 23 [2] 7f 3e [2] 7d 3f [2] 66 39 [2] 7a 3e [2] 66 11 }

  condition:
    any of them
}