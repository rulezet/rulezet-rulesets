rule TTP_XOR_QUAD_CurrentVersionRun_eab3 {
  strings:
    $key_eab3 = { b9 dc [2] 9d d2 [2] b6 fe [2] 98 dc [2] 8c c7 [2] 83 dd [2] 9d c0 [2] 9f c1 [2] 84 c7 [2] 98 c0 [2] 84 ef }

  condition:
    any of them
}