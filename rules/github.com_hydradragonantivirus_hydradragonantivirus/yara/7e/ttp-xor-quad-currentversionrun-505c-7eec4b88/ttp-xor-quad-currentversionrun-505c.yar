rule TTP_XOR_QUAD_CurrentVersionRun_505c {
  strings:
    $key_505c = { 03 33 [2] 27 3d [2] 0c 11 [2] 22 33 [2] 36 28 [2] 39 32 [2] 27 2f [2] 25 2e [2] 3e 28 [2] 22 2f [2] 3e 00 }

  condition:
    any of them
}