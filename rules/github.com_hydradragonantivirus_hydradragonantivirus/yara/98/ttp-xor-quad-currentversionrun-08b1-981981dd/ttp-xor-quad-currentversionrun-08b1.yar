rule TTP_XOR_QUAD_CurrentVersionRun_08b1 {
  strings:
    $key_08b1 = { 5b de [2] 7f d0 [2] 54 fc [2] 7a de [2] 6e c5 [2] 61 df [2] 7f c2 [2] 7d c3 [2] 66 c5 [2] 7a c2 [2] 66 ed }

  condition:
    any of them
}