rule TTP_XOR_QUAD_CurrentVersionRun_afae {
  strings:
    $key_afae = { fc c1 [2] d8 cf [2] f3 e3 [2] dd c1 [2] c9 da [2] c6 c0 [2] d8 dd [2] da dc [2] c1 da [2] dd dd [2] c1 f2 }

  condition:
    any of them
}