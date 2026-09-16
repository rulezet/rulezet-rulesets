rule TTP_XOR_QUAD_CurrentVersionRun_aff6 {
  strings:
    $key_aff6 = { fc 99 [2] d8 97 [2] f3 bb [2] dd 99 [2] c9 82 [2] c6 98 [2] d8 85 [2] da 84 [2] c1 82 [2] dd 85 [2] c1 aa }

  condition:
    any of them
}