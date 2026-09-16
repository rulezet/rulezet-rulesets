rule TTP_XOR_QUAD_CurrentVersionRun_ac69 {
  strings:
    $key_ac69 = { ff 06 [2] db 08 [2] f0 24 [2] de 06 [2] ca 1d [2] c5 07 [2] db 1a [2] d9 1b [2] c2 1d [2] de 1a [2] c2 35 }

  condition:
    any of them
}