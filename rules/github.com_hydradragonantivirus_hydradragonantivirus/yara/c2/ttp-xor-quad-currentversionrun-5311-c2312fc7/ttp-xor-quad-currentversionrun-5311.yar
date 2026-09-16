rule TTP_XOR_QUAD_CurrentVersionRun_5311 {
  strings:
    $key_5311 = { 00 7e [2] 24 70 [2] 0f 5c [2] 21 7e [2] 35 65 [2] 3a 7f [2] 24 62 [2] 26 63 [2] 3d 65 [2] 21 62 [2] 3d 4d }

  condition:
    any of them
}