rule TTP_XOR_QUAD_CurrentVersionRun_5f4c {
  strings:
    $key_5f4c = { 0c 23 [2] 28 2d [2] 03 01 [2] 2d 23 [2] 39 38 [2] 36 22 [2] 28 3f [2] 2a 3e [2] 31 38 [2] 2d 3f [2] 31 10 }

  condition:
    any of them
}