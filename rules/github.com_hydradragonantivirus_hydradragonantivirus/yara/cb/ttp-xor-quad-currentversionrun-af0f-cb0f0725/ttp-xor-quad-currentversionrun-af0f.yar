rule TTP_XOR_QUAD_CurrentVersionRun_af0f {
  strings:
    $key_af0f = { fc 60 [2] d8 6e [2] f3 42 [2] dd 60 [2] c9 7b [2] c6 61 [2] d8 7c [2] da 7d [2] c1 7b [2] dd 7c [2] c1 53 }

  condition:
    any of them
}