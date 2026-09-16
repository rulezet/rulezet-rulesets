rule TTP_XOR_QUAD_CurrentVersionRun_1b4c {
  strings:
    $key_1b4c = { 48 23 [2] 6c 2d [2] 47 01 [2] 69 23 [2] 7d 38 [2] 72 22 [2] 6c 3f [2] 6e 3e [2] 75 38 [2] 69 3f [2] 75 10 }

  condition:
    any of them
}