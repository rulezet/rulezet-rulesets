rule TTP_XOR_QUAD_CurrentVersionRun_fdb3 {
  strings:
    $key_fdb3 = { ae dc [2] 8a d2 [2] a1 fe [2] 8f dc [2] 9b c7 [2] 94 dd [2] 8a c0 [2] 88 c1 [2] 93 c7 [2] 8f c0 [2] 93 ef }

  condition:
    any of them
}