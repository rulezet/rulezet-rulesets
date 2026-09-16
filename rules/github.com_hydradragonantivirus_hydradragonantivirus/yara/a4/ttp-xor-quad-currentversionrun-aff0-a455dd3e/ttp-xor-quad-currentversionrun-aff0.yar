rule TTP_XOR_QUAD_CurrentVersionRun_aff0 {
  strings:
    $key_aff0 = { fc 9f [2] d8 91 [2] f3 bd [2] dd 9f [2] c9 84 [2] c6 9e [2] d8 83 [2] da 82 [2] c1 84 [2] dd 83 [2] c1 ac }

  condition:
    any of them
}