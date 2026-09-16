rule TTP_XOR_QUAD_CurrentVersionRun_3eb1 {
  strings:
    $key_3eb1 = { 6d de [2] 49 d0 [2] 62 fc [2] 4c de [2] 58 c5 [2] 57 df [2] 49 c2 [2] 4b c3 [2] 50 c5 [2] 4c c2 [2] 50 ed }

  condition:
    any of them
}