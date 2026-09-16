rule TTP_XOR_QUAD_CurrentVersionRun_3b5f {
  strings:
    $key_3b5f = { 68 30 [2] 4c 3e [2] 67 12 [2] 49 30 [2] 5d 2b [2] 52 31 [2] 4c 2c [2] 4e 2d [2] 55 2b [2] 49 2c [2] 55 03 }

  condition:
    any of them
}