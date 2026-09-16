rule TTP_XOR_QUAD_CurrentVersionRun_ac5d {
  strings:
    $key_ac5d = { ff 32 [2] db 3c [2] f0 10 [2] de 32 [2] ca 29 [2] c5 33 [2] db 2e [2] d9 2f [2] c2 29 [2] de 2e [2] c2 01 }

  condition:
    any of them
}