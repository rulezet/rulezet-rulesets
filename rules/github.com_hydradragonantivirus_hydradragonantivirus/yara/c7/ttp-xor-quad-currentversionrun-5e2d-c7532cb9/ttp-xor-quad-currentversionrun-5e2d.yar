rule TTP_XOR_QUAD_CurrentVersionRun_5e2d {
  strings:
    $key_5e2d = { 0d 42 [2] 29 4c [2] 02 60 [2] 2c 42 [2] 38 59 [2] 37 43 [2] 29 5e [2] 2b 5f [2] 30 59 [2] 2c 5e [2] 30 71 }

  condition:
    any of them
}