rule TTP_XOR_QUAD_CurrentVersionRun_7742 {
  strings:
    $key_7742 = { 24 2d [2] 00 23 [2] 2b 0f [2] 05 2d [2] 11 36 [2] 1e 2c [2] 00 31 [2] 02 30 [2] 19 36 [2] 05 31 [2] 19 1e }

  condition:
    any of them
}