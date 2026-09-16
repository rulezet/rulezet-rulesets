rule TTP_XOR_QUAD_CurrentVersionRun_0b4c {
  strings:
    $key_0b4c = { 58 23 [2] 7c 2d [2] 57 01 [2] 79 23 [2] 6d 38 [2] 62 22 [2] 7c 3f [2] 7e 3e [2] 65 38 [2] 79 3f [2] 65 10 }

  condition:
    any of them
}