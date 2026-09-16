rule TTP_XOR_QUAD_CurrentVersionRun_78b1 {
  strings:
    $key_78b1 = { 2b de [2] 0f d0 [2] 24 fc [2] 0a de [2] 1e c5 [2] 11 df [2] 0f c2 [2] 0d c3 [2] 16 c5 [2] 0a c2 [2] 16 ed }

  condition:
    any of them
}