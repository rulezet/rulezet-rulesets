rule TTP_XOR_QUAD_CurrentVersionRun_f5ac {
  strings:
    $key_f5ac = { a6 c3 [2] 82 cd [2] a9 e1 [2] 87 c3 [2] 93 d8 [2] 9c c2 [2] 82 df [2] 80 de [2] 9b d8 [2] 87 df [2] 9b f0 }

  condition:
    any of them
}