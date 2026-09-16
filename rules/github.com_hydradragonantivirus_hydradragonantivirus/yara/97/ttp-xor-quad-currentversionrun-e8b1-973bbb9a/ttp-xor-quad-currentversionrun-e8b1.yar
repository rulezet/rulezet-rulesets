rule TTP_XOR_QUAD_CurrentVersionRun_e8b1 {
  strings:
    $key_e8b1 = { bb de [2] 9f d0 [2] b4 fc [2] 9a de [2] 8e c5 [2] 81 df [2] 9f c2 [2] 9d c3 [2] 86 c5 [2] 9a c2 [2] 86 ed }

  condition:
    any of them
}