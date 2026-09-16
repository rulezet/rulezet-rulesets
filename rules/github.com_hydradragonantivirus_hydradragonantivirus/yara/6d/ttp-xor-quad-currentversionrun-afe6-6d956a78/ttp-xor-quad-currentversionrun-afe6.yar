rule TTP_XOR_QUAD_CurrentVersionRun_afe6 {
  strings:
    $key_afe6 = { fc 89 [2] d8 87 [2] f3 ab [2] dd 89 [2] c9 92 [2] c6 88 [2] d8 95 [2] da 94 [2] c1 92 [2] dd 95 [2] c1 ba }

  condition:
    any of them
}