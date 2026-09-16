rule TTP_XOR_QUAD_CurrentVersionRun_6bb1 {
  strings:
    $key_6bb1 = { 38 de [2] 1c d0 [2] 37 fc [2] 19 de [2] 0d c5 [2] 02 df [2] 1c c2 [2] 1e c3 [2] 05 c5 [2] 19 c2 [2] 05 ed }

  condition:
    any of them
}