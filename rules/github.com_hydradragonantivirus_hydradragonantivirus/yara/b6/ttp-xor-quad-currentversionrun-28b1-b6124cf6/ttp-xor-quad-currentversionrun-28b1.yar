rule TTP_XOR_QUAD_CurrentVersionRun_28b1 {
  strings:
    $key_28b1 = { 7b de [2] 5f d0 [2] 74 fc [2] 5a de [2] 4e c5 [2] 41 df [2] 5f c2 [2] 5d c3 [2] 46 c5 [2] 5a c2 [2] 46 ed }

  condition:
    any of them
}