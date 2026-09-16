rule TTP_XOR_QUAD_CurrentVersionRun_11b3 {
  strings:
    $key_11b3 = { 42 dc [2] 66 d2 [2] 4d fe [2] 63 dc [2] 77 c7 [2] 78 dd [2] 66 c0 [2] 64 c1 [2] 7f c7 [2] 63 c0 [2] 7f ef }

  condition:
    any of them
}