rule TTP_XOR_QUAD_CurrentVersionRun_484c {
  strings:
    $key_484c = { 1b 23 [2] 3f 2d [2] 14 01 [2] 3a 23 [2] 2e 38 [2] 21 22 [2] 3f 3f [2] 3d 3e [2] 26 38 [2] 3a 3f [2] 26 10 }

  condition:
    any of them
}