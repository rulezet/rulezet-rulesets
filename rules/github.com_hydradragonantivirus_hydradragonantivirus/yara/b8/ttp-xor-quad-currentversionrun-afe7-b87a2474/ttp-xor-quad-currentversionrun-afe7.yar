rule TTP_XOR_QUAD_CurrentVersionRun_afe7 {
  strings:
    $key_afe7 = { fc 88 [2] d8 86 [2] f3 aa [2] dd 88 [2] c9 93 [2] c6 89 [2] d8 94 [2] da 95 [2] c1 93 [2] dd 94 [2] c1 bb }

  condition:
    any of them
}