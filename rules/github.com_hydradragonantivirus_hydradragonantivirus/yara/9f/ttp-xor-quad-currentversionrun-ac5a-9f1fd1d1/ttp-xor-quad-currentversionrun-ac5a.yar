rule TTP_XOR_QUAD_CurrentVersionRun_ac5a {
  strings:
    $key_ac5a = { ff 35 [2] db 3b [2] f0 17 [2] de 35 [2] ca 2e [2] c5 34 [2] db 29 [2] d9 28 [2] c2 2e [2] de 29 [2] c2 06 }

  condition:
    any of them
}