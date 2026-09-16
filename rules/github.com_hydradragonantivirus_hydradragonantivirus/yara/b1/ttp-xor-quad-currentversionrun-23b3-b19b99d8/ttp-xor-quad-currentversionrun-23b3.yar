rule TTP_XOR_QUAD_CurrentVersionRun_23b3 {
  strings:
    $key_23b3 = { 70 dc [2] 54 d2 [2] 7f fe [2] 51 dc [2] 45 c7 [2] 4a dd [2] 54 c0 [2] 56 c1 [2] 4d c7 [2] 51 c0 [2] 4d ef }

  condition:
    any of them
}