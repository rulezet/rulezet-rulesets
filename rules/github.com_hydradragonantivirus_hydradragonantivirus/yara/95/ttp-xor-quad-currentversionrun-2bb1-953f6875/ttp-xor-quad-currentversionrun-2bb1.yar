rule TTP_XOR_QUAD_CurrentVersionRun_2bb1 {
  strings:
    $key_2bb1 = { 78 de [2] 5c d0 [2] 77 fc [2] 59 de [2] 4d c5 [2] 42 df [2] 5c c2 [2] 5e c3 [2] 45 c5 [2] 59 c2 [2] 45 ed }

  condition:
    any of them
}