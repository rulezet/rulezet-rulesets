rule TTP_XOR_QUAD_CurrentVersionRun_764d {
  strings:
    $key_764d = { 25 22 [2] 01 2c [2] 2a 00 [2] 04 22 [2] 10 39 [2] 1f 23 [2] 01 3e [2] 03 3f [2] 18 39 [2] 04 3e [2] 18 11 }

  condition:
    any of them
}