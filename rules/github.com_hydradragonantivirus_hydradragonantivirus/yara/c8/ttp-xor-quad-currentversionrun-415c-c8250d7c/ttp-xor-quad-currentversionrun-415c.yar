rule TTP_XOR_QUAD_CurrentVersionRun_415c {
  strings:
    $key_415c = { 12 33 [2] 36 3d [2] 1d 11 [2] 33 33 [2] 27 28 [2] 28 32 [2] 36 2f [2] 34 2e [2] 2f 28 [2] 33 2f [2] 2f 00 }

  condition:
    any of them
}