rule TTP_XOR_QUAD_CurrentVersionRun_33b3 {
  strings:
    $key_33b3 = { 60 dc [2] 44 d2 [2] 6f fe [2] 41 dc [2] 55 c7 [2] 5a dd [2] 44 c0 [2] 46 c1 [2] 5d c7 [2] 41 c0 [2] 5d ef }

  condition:
    any of them
}