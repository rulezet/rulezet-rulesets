rule TTP_XOR_QUAD_CurrentVersionRun_2d5f {
  strings:
    $key_2d5f = { 7e 30 [2] 5a 3e [2] 71 12 [2] 5f 30 [2] 4b 2b [2] 44 31 [2] 5a 2c [2] 58 2d [2] 43 2b [2] 5f 2c [2] 43 03 }

  condition:
    any of them
}