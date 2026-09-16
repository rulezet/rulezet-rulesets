rule TTP_XOR_QUAD_CurrentVersionRun_6a61 {
  strings:
    $key_6a61 = { 39 0e [2] 1d 00 [2] 36 2c [2] 18 0e [2] 0c 15 [2] 03 0f [2] 1d 12 [2] 1f 13 [2] 04 15 [2] 18 12 [2] 04 3d }

  condition:
    any of them
}