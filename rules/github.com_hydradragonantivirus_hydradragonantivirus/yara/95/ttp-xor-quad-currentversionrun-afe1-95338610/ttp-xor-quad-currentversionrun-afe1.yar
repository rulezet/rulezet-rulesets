rule TTP_XOR_QUAD_CurrentVersionRun_afe1 {
  strings:
    $key_afe1 = { fc 8e [2] d8 80 [2] f3 ac [2] dd 8e [2] c9 95 [2] c6 8f [2] d8 92 [2] da 93 [2] c1 95 [2] dd 92 [2] c1 bd }

  condition:
    any of them
}