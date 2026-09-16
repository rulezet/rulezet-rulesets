rule TTP_XOR_QUAD_CurrentVersionRun_5db3 {
  strings:
    $key_5db3 = { 0e dc [2] 2a d2 [2] 01 fe [2] 2f dc [2] 3b c7 [2] 34 dd [2] 2a c0 [2] 28 c1 [2] 33 c7 [2] 2f c0 [2] 33 ef }

  condition:
    any of them
}