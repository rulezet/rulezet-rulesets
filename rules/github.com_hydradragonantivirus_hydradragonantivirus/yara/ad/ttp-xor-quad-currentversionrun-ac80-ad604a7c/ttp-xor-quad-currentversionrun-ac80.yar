rule TTP_XOR_QUAD_CurrentVersionRun_ac80 {
  strings:
    $key_ac80 = { ff ef [2] db e1 [2] f0 cd [2] de ef [2] ca f4 [2] c5 ee [2] db f3 [2] d9 f2 [2] c2 f4 [2] de f3 [2] c2 dc }

  condition:
    any of them
}