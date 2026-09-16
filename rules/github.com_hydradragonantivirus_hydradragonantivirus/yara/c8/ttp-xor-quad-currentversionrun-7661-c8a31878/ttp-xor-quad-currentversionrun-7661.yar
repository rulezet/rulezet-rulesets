rule TTP_XOR_QUAD_CurrentVersionRun_7661 {
  strings:
    $key_7661 = { 25 0e [2] 01 00 [2] 2a 2c [2] 04 0e [2] 10 15 [2] 1f 0f [2] 01 12 [2] 03 13 [2] 18 15 [2] 04 12 [2] 18 3d }

  condition:
    any of them
}