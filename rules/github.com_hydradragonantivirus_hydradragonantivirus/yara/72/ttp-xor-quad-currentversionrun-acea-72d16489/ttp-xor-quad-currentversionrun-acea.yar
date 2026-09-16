rule TTP_XOR_QUAD_CurrentVersionRun_acea {
  strings:
    $key_acea = { ff 85 [2] db 8b [2] f0 a7 [2] de 85 [2] ca 9e [2] c5 84 [2] db 99 [2] d9 98 [2] c2 9e [2] de 99 [2] c2 b6 }

  condition:
    any of them
}