rule TTP_XOR_QUAD_CurrentVersionRun_71b1 {
  strings:
    $key_71b1 = { 22 de [2] 06 d0 [2] 2d fc [2] 03 de [2] 17 c5 [2] 18 df [2] 06 c2 [2] 04 c3 [2] 1f c5 [2] 03 c2 [2] 1f ed }

  condition:
    any of them
}