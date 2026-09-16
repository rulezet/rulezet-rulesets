rule TTP_XOR_QUAD_CurrentVersionRun_1a4c {
  strings:
    $key_1a4c = { 49 23 [2] 6d 2d [2] 46 01 [2] 68 23 [2] 7c 38 [2] 73 22 [2] 6d 3f [2] 6f 3e [2] 74 38 [2] 68 3f [2] 74 10 }

  condition:
    any of them
}