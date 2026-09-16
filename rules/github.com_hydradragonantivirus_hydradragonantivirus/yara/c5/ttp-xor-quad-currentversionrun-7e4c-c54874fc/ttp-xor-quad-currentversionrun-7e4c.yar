rule TTP_XOR_QUAD_CurrentVersionRun_7e4c {
  strings:
    $key_7e4c = { 2d 23 [2] 09 2d [2] 22 01 [2] 0c 23 [2] 18 38 [2] 17 22 [2] 09 3f [2] 0b 3e [2] 10 38 [2] 0c 3f [2] 10 10 }

  condition:
    any of them
}