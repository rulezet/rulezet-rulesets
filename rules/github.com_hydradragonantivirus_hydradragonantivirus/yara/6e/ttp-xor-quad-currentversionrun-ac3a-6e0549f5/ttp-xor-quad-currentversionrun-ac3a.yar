rule TTP_XOR_QUAD_CurrentVersionRun_ac3a {
  strings:
    $key_ac3a = { ff 55 [2] db 5b [2] f0 77 [2] de 55 [2] ca 4e [2] c5 54 [2] db 49 [2] d9 48 [2] c2 4e [2] de 49 [2] c2 66 }

  condition:
    any of them
}