rule TTP_XOR_QUAD_CurrentVersionRun_1db3 {
  strings:
    $key_1db3 = { 4e dc [2] 6a d2 [2] 41 fe [2] 6f dc [2] 7b c7 [2] 74 dd [2] 6a c0 [2] 68 c1 [2] 73 c7 [2] 6f c0 [2] 73 ef }

  condition:
    any of them
}