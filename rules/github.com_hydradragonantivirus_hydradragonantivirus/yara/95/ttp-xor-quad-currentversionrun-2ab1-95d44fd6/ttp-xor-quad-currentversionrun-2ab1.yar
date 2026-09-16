rule TTP_XOR_QUAD_CurrentVersionRun_2ab1 {
  strings:
    $key_2ab1 = { 79 de [2] 5d d0 [2] 76 fc [2] 58 de [2] 4c c5 [2] 43 df [2] 5d c2 [2] 5f c3 [2] 44 c5 [2] 58 c2 [2] 44 ed }

  condition:
    any of them
}