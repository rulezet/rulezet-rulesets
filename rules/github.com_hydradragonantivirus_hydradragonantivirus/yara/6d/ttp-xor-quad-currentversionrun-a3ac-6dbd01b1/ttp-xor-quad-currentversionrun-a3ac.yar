rule TTP_XOR_QUAD_CurrentVersionRun_a3ac {
  strings:
    $key_a3ac = { f0 c3 [2] d4 cd [2] ff e1 [2] d1 c3 [2] c5 d8 [2] ca c2 [2] d4 df [2] d6 de [2] cd d8 [2] d1 df [2] cd f0 }

  condition:
    any of them
}