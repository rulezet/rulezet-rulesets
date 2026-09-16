rule TTP_XOR_QUAD_CurrentVersionRun_3bb1 {
  strings:
    $key_3bb1 = { 68 de [2] 4c d0 [2] 67 fc [2] 49 de [2] 5d c5 [2] 52 df [2] 4c c2 [2] 4e c3 [2] 55 c5 [2] 49 c2 [2] 55 ed }

  condition:
    any of them
}