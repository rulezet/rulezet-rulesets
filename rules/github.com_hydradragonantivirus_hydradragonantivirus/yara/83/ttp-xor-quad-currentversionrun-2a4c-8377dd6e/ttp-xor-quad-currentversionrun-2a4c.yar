rule TTP_XOR_QUAD_CurrentVersionRun_2a4c {
  strings:
    $key_2a4c = { 79 23 [2] 5d 2d [2] 76 01 [2] 58 23 [2] 4c 38 [2] 43 22 [2] 5d 3f [2] 5f 3e [2] 44 38 [2] 58 3f [2] 44 10 }

  condition:
    any of them
}