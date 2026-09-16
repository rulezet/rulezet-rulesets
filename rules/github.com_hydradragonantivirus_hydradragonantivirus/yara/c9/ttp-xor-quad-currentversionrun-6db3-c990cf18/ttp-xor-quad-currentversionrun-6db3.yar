rule TTP_XOR_QUAD_CurrentVersionRun_6db3 {
  strings:
    $key_6db3 = { 3e dc [2] 1a d2 [2] 31 fe [2] 1f dc [2] 0b c7 [2] 04 dd [2] 1a c0 [2] 18 c1 [2] 03 c7 [2] 1f c0 [2] 03 ef }

  condition:
    any of them
}