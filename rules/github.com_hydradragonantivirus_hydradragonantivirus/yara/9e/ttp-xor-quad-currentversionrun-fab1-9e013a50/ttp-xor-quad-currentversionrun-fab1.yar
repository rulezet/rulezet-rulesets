rule TTP_XOR_QUAD_CurrentVersionRun_fab1 {
  strings:
    $key_fab1 = { a9 de [2] 8d d0 [2] a6 fc [2] 88 de [2] 9c c5 [2] 93 df [2] 8d c2 [2] 8f c3 [2] 94 c5 [2] 88 c2 [2] 94 ed }

  condition:
    any of them
}