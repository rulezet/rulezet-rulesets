rule TTP_XOR_QUAD_CurrentVersionRun_afb3 {
  strings:
    $key_afb3 = { fc dc [2] d8 d2 [2] f3 fe [2] dd dc [2] c9 c7 [2] c6 dd [2] d8 c0 [2] da c1 [2] c1 c7 [2] dd c0 [2] c1 ef }

  condition:
    any of them
}