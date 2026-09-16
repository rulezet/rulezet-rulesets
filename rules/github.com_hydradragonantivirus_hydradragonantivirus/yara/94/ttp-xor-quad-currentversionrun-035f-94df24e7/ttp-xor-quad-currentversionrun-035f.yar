rule TTP_XOR_QUAD_CurrentVersionRun_035f {
  strings:
    $key_035f = { 50 30 [2] 74 3e [2] 5f 12 [2] 71 30 [2] 65 2b [2] 6a 31 [2] 74 2c [2] 76 2d [2] 6d 2b [2] 71 2c [2] 6d 03 }

  condition:
    any of them
}