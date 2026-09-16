rule TTP_XOR_QUAD_CurrentVersionRun_76b3 {
  strings:
    $key_76b3 = { 25 dc [2] 01 d2 [2] 2a fe [2] 04 dc [2] 10 c7 [2] 1f dd [2] 01 c0 [2] 03 c1 [2] 18 c7 [2] 04 c0 [2] 18 ef }

  condition:
    any of them
}