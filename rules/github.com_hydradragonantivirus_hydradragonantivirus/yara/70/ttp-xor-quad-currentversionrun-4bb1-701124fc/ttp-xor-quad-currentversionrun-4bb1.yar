rule TTP_XOR_QUAD_CurrentVersionRun_4bb1 {
  strings:
    $key_4bb1 = { 18 de [2] 3c d0 [2] 17 fc [2] 39 de [2] 2d c5 [2] 22 df [2] 3c c2 [2] 3e c3 [2] 25 c5 [2] 39 c2 [2] 25 ed }

  condition:
    any of them
}