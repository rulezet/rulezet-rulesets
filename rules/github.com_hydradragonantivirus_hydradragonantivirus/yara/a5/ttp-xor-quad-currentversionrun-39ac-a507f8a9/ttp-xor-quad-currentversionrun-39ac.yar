rule TTP_XOR_QUAD_CurrentVersionRun_39ac {
  strings:
    $key_39ac = { 6a c3 [2] 4e cd [2] 65 e1 [2] 4b c3 [2] 5f d8 [2] 50 c2 [2] 4e df [2] 4c de [2] 57 d8 [2] 4b df [2] 57 f0 }

  condition:
    any of them
}