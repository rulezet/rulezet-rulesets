rule TTP_XOR_QUAD_CurrentVersionRun_2db3 {
  strings:
    $key_2db3 = { 7e dc [2] 5a d2 [2] 71 fe [2] 5f dc [2] 4b c7 [2] 44 dd [2] 5a c0 [2] 58 c1 [2] 43 c7 [2] 5f c0 [2] 43 ef }

  condition:
    any of them
}