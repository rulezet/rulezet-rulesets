rule TTP_XOR_QUAD_CurrentVersionRun_734d {
  strings:
    $key_734d = { 20 22 [2] 04 2c [2] 2f 00 [2] 01 22 [2] 15 39 [2] 1a 23 [2] 04 3e [2] 06 3f [2] 1d 39 [2] 01 3e [2] 1d 11 }

  condition:
    any of them
}