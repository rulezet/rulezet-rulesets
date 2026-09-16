rule TTP_XOR_QUAD_CurrentVersionRun_07ac {
  strings:
    $key_07ac = { 54 c3 [2] 70 cd [2] 5b e1 [2] 75 c3 [2] 61 d8 [2] 6e c2 [2] 70 df [2] 72 de [2] 69 d8 [2] 75 df [2] 69 f0 }

  condition:
    any of them
}