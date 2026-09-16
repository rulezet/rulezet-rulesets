rule TTP_XOR_QUAD_CurrentVersionRun_a8ac {
  strings:
    $key_a8ac = { fb c3 [2] df cd [2] f4 e1 [2] da c3 [2] ce d8 [2] c1 c2 [2] df df [2] dd de [2] c6 d8 [2] da df [2] c6 f0 }

  condition:
    any of them
}