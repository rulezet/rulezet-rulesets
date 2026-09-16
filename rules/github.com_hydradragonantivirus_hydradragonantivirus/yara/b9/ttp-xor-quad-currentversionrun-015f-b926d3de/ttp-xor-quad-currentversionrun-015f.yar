rule TTP_XOR_QUAD_CurrentVersionRun_015f {
  strings:
    $key_015f = { 52 30 [2] 76 3e [2] 5d 12 [2] 73 30 [2] 67 2b [2] 68 31 [2] 76 2c [2] 74 2d [2] 6f 2b [2] 73 2c [2] 6f 03 }

  condition:
    any of them
}