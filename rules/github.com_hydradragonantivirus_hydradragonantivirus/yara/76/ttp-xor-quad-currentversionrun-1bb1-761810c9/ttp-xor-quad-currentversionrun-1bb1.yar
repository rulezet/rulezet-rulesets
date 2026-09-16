rule TTP_XOR_QUAD_CurrentVersionRun_1bb1 {
  strings:
    $key_1bb1 = { 48 de [2] 6c d0 [2] 47 fc [2] 69 de [2] 7d c5 [2] 72 df [2] 6c c2 [2] 6e c3 [2] 75 c5 [2] 69 c2 [2] 75 ed }

  condition:
    any of them
}