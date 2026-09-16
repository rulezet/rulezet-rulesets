rule TTP_XOR_QUAD_CurrentVersionRun_714c {
  strings:
    $key_714c = { 22 23 [2] 06 2d [2] 2d 01 [2] 03 23 [2] 17 38 [2] 18 22 [2] 06 3f [2] 04 3e [2] 1f 38 [2] 03 3f [2] 1f 10 }

  condition:
    any of them
}