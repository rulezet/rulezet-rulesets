rule TTP_XOR_QUAD_CurrentVersionRun_29ac {
  strings:
    $key_29ac = { 7a c3 [2] 5e cd [2] 75 e1 [2] 5b c3 [2] 4f d8 [2] 40 c2 [2] 5e df [2] 5c de [2] 47 d8 [2] 5b df [2] 47 f0 }

  condition:
    any of them
}