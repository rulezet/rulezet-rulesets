rule TTP_XOR_QUAD_CurrentVersionRun_4db3 {
  strings:
    $key_4db3 = { 1e dc [2] 3a d2 [2] 11 fe [2] 3f dc [2] 2b c7 [2] 24 dd [2] 3a c0 [2] 38 c1 [2] 23 c7 [2] 3f c0 [2] 23 ef }

  condition:
    any of them
}