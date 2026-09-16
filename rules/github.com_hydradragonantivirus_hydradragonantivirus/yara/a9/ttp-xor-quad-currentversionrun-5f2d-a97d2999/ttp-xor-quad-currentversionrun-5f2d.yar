rule TTP_XOR_QUAD_CurrentVersionRun_5f2d {
  strings:
    $key_5f2d = { 0c 42 [2] 28 4c [2] 03 60 [2] 2d 42 [2] 39 59 [2] 36 43 [2] 28 5e [2] 2a 5f [2] 31 59 [2] 2d 5e [2] 31 71 }

  condition:
    any of them
}