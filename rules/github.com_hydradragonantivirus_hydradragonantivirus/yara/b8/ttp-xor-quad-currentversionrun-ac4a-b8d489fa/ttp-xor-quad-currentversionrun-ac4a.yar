rule TTP_XOR_QUAD_CurrentVersionRun_ac4a {
  strings:
    $key_ac4a = { ff 25 [2] db 2b [2] f0 07 [2] de 25 [2] ca 3e [2] c5 24 [2] db 39 [2] d9 38 [2] c2 3e [2] de 39 [2] c2 16 }

  condition:
    any of them
}