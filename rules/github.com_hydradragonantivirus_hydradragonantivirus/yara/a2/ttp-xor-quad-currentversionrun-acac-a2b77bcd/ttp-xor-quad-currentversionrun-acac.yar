rule TTP_XOR_QUAD_CurrentVersionRun_acac {
  strings:
    $key_acac = { ff c3 [2] db cd [2] f0 e1 [2] de c3 [2] ca d8 [2] c5 c2 [2] db df [2] d9 de [2] c2 d8 [2] de df [2] c2 f0 }

  condition:
    any of them
}