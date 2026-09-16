rule TTP_XOR_QUAD_CurrentVersionRun_3f61 {
  strings:
    $key_3f61 = { 6c 0e [2] 48 00 [2] 63 2c [2] 4d 0e [2] 59 15 [2] 56 0f [2] 48 12 [2] 4a 13 [2] 51 15 [2] 4d 12 [2] 51 3d }

  condition:
    any of them
}