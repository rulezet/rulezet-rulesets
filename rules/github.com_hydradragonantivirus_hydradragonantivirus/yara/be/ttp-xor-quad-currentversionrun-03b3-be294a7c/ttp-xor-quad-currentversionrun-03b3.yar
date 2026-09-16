rule TTP_XOR_QUAD_CurrentVersionRun_03b3 {
  strings:
    $key_03b3 = { 50 dc [2] 74 d2 [2] 5f fe [2] 71 dc [2] 65 c7 [2] 6a dd [2] 74 c0 [2] 76 c1 [2] 6d c7 [2] 71 c0 [2] 6d ef }

  condition:
    any of them
}