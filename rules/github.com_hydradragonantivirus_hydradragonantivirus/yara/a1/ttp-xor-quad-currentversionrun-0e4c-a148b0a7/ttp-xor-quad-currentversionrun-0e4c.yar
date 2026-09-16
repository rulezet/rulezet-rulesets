rule TTP_XOR_QUAD_CurrentVersionRun_0e4c {
  strings:
    $key_0e4c = { 5d 23 [2] 79 2d [2] 52 01 [2] 7c 23 [2] 68 38 [2] 67 22 [2] 79 3f [2] 7b 3e [2] 60 38 [2] 7c 3f [2] 60 10 }

  condition:
    any of them
}