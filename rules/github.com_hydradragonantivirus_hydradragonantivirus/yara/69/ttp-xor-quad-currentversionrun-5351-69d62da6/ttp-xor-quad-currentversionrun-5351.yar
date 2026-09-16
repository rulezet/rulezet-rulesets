rule TTP_XOR_QUAD_CurrentVersionRun_5351 {
  strings:
    $key_5351 = { 00 3e [2] 24 30 [2] 0f 1c [2] 21 3e [2] 35 25 [2] 3a 3f [2] 24 22 [2] 26 23 [2] 3d 25 [2] 21 22 [2] 3d 0d }

  condition:
    any of them
}