rule TTP_XOR_QUAD_CurrentVersionRun_af9d {
  strings:
    $key_af9d = { fc f2 [2] d8 fc [2] f3 d0 [2] dd f2 [2] c9 e9 [2] c6 f3 [2] d8 ee [2] da ef [2] c1 e9 [2] dd ee [2] c1 c1 }

  condition:
    any of them
}