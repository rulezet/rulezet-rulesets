rule TTP_XOR_QUAD_CurrentVersionRun_044c {
  strings:
    $key_044c = { 57 23 [2] 73 2d [2] 58 01 [2] 76 23 [2] 62 38 [2] 6d 22 [2] 73 3f [2] 71 3e [2] 6a 38 [2] 76 3f [2] 6a 10 }

  condition:
    any of them
}