rule TTP_XOR_QUAD_CurrentVersionRun_3ab3 {
  strings:
    $key_3ab3 = { 69 dc [2] 4d d2 [2] 66 fe [2] 48 dc [2] 5c c7 [2] 53 dd [2] 4d c0 [2] 4f c1 [2] 54 c7 [2] 48 c0 [2] 54 ef }

  condition:
    any of them
}