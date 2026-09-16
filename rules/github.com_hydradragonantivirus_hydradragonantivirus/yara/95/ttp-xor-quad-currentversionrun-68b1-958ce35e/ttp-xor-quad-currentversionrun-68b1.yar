rule TTP_XOR_QUAD_CurrentVersionRun_68b1 {
  strings:
    $key_68b1 = { 3b de [2] 1f d0 [2] 34 fc [2] 1a de [2] 0e c5 [2] 01 df [2] 1f c2 [2] 1d c3 [2] 06 c5 [2] 1a c2 [2] 06 ed }

  condition:
    any of them
}