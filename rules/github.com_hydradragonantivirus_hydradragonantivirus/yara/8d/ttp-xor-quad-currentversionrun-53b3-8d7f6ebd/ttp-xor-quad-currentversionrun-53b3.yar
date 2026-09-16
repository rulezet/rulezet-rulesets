rule TTP_XOR_QUAD_CurrentVersionRun_53b3 {
  strings:
    $key_53b3 = { 00 dc [2] 24 d2 [2] 0f fe [2] 21 dc [2] 35 c7 [2] 3a dd [2] 24 c0 [2] 26 c1 [2] 3d c7 [2] 21 c0 [2] 3d ef }

  condition:
    any of them
}