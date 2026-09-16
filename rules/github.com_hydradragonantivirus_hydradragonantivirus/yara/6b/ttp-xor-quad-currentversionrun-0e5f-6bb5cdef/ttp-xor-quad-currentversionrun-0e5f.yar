rule TTP_XOR_QUAD_CurrentVersionRun_0e5f {
  strings:
    $key_0e5f = { 5d 30 [2] 79 3e [2] 52 12 [2] 7c 30 [2] 68 2b [2] 67 31 [2] 79 2c [2] 7b 2d [2] 60 2b [2] 7c 2c [2] 60 03 }

  condition:
    any of them
}