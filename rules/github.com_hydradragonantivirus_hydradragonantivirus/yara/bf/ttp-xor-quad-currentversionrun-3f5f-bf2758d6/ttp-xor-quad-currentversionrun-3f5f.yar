rule TTP_XOR_QUAD_CurrentVersionRun_3f5f {
  strings:
    $key_3f5f = { 6c 30 [2] 48 3e [2] 63 12 [2] 4d 30 [2] 59 2b [2] 56 31 [2] 48 2c [2] 4a 2d [2] 51 2b [2] 4d 2c [2] 51 03 }

  condition:
    any of them
}