rule TTP_XOR_QUAD_CurrentVersionRun_afe0 {
  strings:
    $key_afe0 = { fc 8f [2] d8 81 [2] f3 ad [2] dd 8f [2] c9 94 [2] c6 8e [2] d8 93 [2] da 92 [2] c1 94 [2] dd 93 [2] c1 bc }

  condition:
    any of them
}