rule TTP_XOR_QUAD_CurrentVersionRun_fab3 {
  strings:
    $key_fab3 = { a9 dc [2] 8d d2 [2] a6 fe [2] 88 dc [2] 9c c7 [2] 93 dd [2] 8d c0 [2] 8f c1 [2] 94 c7 [2] 88 c0 [2] 94 ef }

  condition:
    any of them
}