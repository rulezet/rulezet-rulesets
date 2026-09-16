rule TTP_XOR_QUAD_CurrentVersionRun_1661 {
  strings:
    $key_1661 = { 45 0e [2] 61 00 [2] 4a 2c [2] 64 0e [2] 70 15 [2] 7f 0f [2] 61 12 [2] 63 13 [2] 78 15 [2] 64 12 [2] 78 3d }

  condition:
    any of them
}