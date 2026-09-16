rule TTP_XOR_QUAD_CurrentVersionRun_1d4c {
  strings:
    $key_1d4c = { 4e 23 [2] 6a 2d [2] 41 01 [2] 6f 23 [2] 7b 38 [2] 74 22 [2] 6a 3f [2] 68 3e [2] 73 38 [2] 6f 3f [2] 73 10 }

  condition:
    any of them
}