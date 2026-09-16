rule TTP_XOR_QUAD_CurrentVersionRun_1f4c {
  strings:
    $key_1f4c = { 4c 23 [2] 68 2d [2] 43 01 [2] 6d 23 [2] 79 38 [2] 76 22 [2] 68 3f [2] 6a 3e [2] 71 38 [2] 6d 3f [2] 71 10 }

  condition:
    any of them
}