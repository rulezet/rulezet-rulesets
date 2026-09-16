rule TTP_XOR_QUAD_CurrentVersionRun_02b1 {
  strings:
    $key_02b1 = { 51 de [2] 75 d0 [2] 5e fc [2] 70 de [2] 64 c5 [2] 6b df [2] 75 c2 [2] 77 c3 [2] 6c c5 [2] 70 c2 [2] 6c ed }

  condition:
    any of them
}