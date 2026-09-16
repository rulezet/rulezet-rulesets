rule TTP_XOR_QUAD_CurrentVersionRun_f2b1 {
  strings:
    $key_f2b1 = { a1 de [2] 85 d0 [2] ae fc [2] 80 de [2] 94 c5 [2] 9b df [2] 85 c2 [2] 87 c3 [2] 9c c5 [2] 80 c2 [2] 9c ed }

  condition:
    any of them
}