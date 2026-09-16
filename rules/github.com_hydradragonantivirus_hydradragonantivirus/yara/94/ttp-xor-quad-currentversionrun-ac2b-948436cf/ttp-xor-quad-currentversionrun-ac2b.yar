rule TTP_XOR_QUAD_CurrentVersionRun_ac2b {
  strings:
    $key_ac2b = { ff 44 [2] db 4a [2] f0 66 [2] de 44 [2] ca 5f [2] c5 45 [2] db 58 [2] d9 59 [2] c2 5f [2] de 58 [2] c2 77 }

  condition:
    any of them
}