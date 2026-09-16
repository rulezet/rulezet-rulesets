rule TTP_XOR_QUAD_CurrentVersionRun_22b1 {
  strings:
    $key_22b1 = { 71 de [2] 55 d0 [2] 7e fc [2] 50 de [2] 44 c5 [2] 4b df [2] 55 c2 [2] 57 c3 [2] 4c c5 [2] 50 c2 [2] 4c ed }

  condition:
    any of them
}