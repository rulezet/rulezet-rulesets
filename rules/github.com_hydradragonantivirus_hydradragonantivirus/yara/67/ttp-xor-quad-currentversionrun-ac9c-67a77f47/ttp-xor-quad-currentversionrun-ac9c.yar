rule TTP_XOR_QUAD_CurrentVersionRun_ac9c {
  strings:
    $key_ac9c = { ff f3 [2] db fd [2] f0 d1 [2] de f3 [2] ca e8 [2] c5 f2 [2] db ef [2] d9 ee [2] c2 e8 [2] de ef [2] c2 c0 }

  condition:
    any of them
}