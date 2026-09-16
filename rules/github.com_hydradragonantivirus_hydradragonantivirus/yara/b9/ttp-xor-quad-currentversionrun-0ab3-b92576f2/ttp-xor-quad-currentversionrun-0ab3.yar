rule TTP_XOR_QUAD_CurrentVersionRun_0ab3 {
  strings:
    $key_0ab3 = { 59 dc [2] 7d d2 [2] 56 fe [2] 78 dc [2] 6c c7 [2] 63 dd [2] 7d c0 [2] 7f c1 [2] 64 c7 [2] 78 c0 [2] 64 ef }

  condition:
    any of them
}