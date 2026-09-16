rule TTP_XOR_QUAD_CurrentVersionRun_a5ac {
  strings:
    $key_a5ac = { f6 c3 [2] d2 cd [2] f9 e1 [2] d7 c3 [2] c3 d8 [2] cc c2 [2] d2 df [2] d0 de [2] cb d8 [2] d7 df [2] cb f0 }

  condition:
    any of them
}