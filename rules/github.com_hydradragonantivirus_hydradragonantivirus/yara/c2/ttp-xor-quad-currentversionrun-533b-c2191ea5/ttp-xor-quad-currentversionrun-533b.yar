rule TTP_XOR_QUAD_CurrentVersionRun_533b {
  strings:
    $key_533b = { 00 54 [2] 24 5a [2] 0f 76 [2] 21 54 [2] 35 4f [2] 3a 55 [2] 24 48 [2] 26 49 [2] 3d 4f [2] 21 48 [2] 3d 67 }

  condition:
    any of them
}