rule TTP_XOR_QUAD_CurrentVersionRun_0ab1 {
  strings:
    $key_0ab1 = { 59 de [2] 7d d0 [2] 56 fc [2] 78 de [2] 6c c5 [2] 63 df [2] 7d c2 [2] 7f c3 [2] 64 c5 [2] 78 c2 [2] 64 ed }

  condition:
    any of them
}