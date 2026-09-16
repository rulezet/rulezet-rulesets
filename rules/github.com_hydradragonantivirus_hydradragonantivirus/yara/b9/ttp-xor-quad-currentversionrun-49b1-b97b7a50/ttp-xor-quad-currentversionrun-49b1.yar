rule TTP_XOR_QUAD_CurrentVersionRun_49b1 {
  strings:
    $key_49b1 = { 1a de [2] 3e d0 [2] 15 fc [2] 3b de [2] 2f c5 [2] 20 df [2] 3e c2 [2] 3c c3 [2] 27 c5 [2] 3b c2 [2] 27 ed }

  condition:
    any of them
}