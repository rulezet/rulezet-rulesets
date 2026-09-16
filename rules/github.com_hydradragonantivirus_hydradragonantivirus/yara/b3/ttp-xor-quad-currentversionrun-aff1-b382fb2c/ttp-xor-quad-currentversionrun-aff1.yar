rule TTP_XOR_QUAD_CurrentVersionRun_aff1 {
  strings:
    $key_aff1 = { fc 9e [2] d8 90 [2] f3 bc [2] dd 9e [2] c9 85 [2] c6 9f [2] d8 82 [2] da 83 [2] c1 85 [2] dd 82 [2] c1 ad }

  condition:
    any of them
}