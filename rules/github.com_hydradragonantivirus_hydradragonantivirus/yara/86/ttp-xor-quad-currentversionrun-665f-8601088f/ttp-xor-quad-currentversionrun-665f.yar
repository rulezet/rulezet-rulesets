rule TTP_XOR_QUAD_CurrentVersionRun_665f {
  strings:
    $key_665f = { 35 30 [2] 11 3e [2] 3a 12 [2] 14 30 [2] 00 2b [2] 0f 31 [2] 11 2c [2] 13 2d [2] 08 2b [2] 14 2c [2] 08 03 }

  condition:
    any of them
}