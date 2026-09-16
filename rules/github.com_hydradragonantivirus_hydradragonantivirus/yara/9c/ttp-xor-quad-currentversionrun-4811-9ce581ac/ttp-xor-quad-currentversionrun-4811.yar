rule TTP_XOR_QUAD_CurrentVersionRun_4811 {
  strings:
    $key_4811 = { 1b 7e [2] 3f 70 [2] 14 5c [2] 3a 7e [2] 2e 65 [2] 21 7f [2] 3f 62 [2] 3d 63 [2] 26 65 [2] 3a 62 [2] 26 4d }

  condition:
    any of them
}