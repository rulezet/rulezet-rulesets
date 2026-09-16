rule TTP_XOR_QUAD_CurrentVersionRun_ac68 {
  strings:
    $key_ac68 = { ff 07 [2] db 09 [2] f0 25 [2] de 07 [2] ca 1c [2] c5 06 [2] db 1b [2] d9 1a [2] c2 1c [2] de 1b [2] c2 34 }

  condition:
    any of them
}