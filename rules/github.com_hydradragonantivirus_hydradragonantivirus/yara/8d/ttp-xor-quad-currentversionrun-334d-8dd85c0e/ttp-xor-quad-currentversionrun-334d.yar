rule TTP_XOR_QUAD_CurrentVersionRun_334d {
  strings:
    $key_334d = { 60 22 [2] 44 2c [2] 6f 00 [2] 41 22 [2] 55 39 [2] 5a 23 [2] 44 3e [2] 46 3f [2] 5d 39 [2] 41 3e [2] 5d 11 }

  condition:
    any of them
}