rule TTP_XOR_QUAD_CurrentVersionRun_48b1 {
  strings:
    $key_48b1 = { 1b de [2] 3f d0 [2] 14 fc [2] 3a de [2] 2e c5 [2] 21 df [2] 3f c2 [2] 3d c3 [2] 26 c5 [2] 3a c2 [2] 26 ed }

  condition:
    any of them
}