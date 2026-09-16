rule TTP_XOR_QUAD_CurrentVersionRun_1ab3 {
  strings:
    $key_1ab3 = { 49 dc [2] 6d d2 [2] 46 fe [2] 68 dc [2] 7c c7 [2] 73 dd [2] 6d c0 [2] 6f c1 [2] 74 c7 [2] 68 c0 [2] 74 ef }

  condition:
    any of them
}