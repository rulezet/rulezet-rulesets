rule TTP_XOR_QUAD_CurrentVersionRun_ac78 {
  strings:
    $key_ac78 = { ff 17 [2] db 19 [2] f0 35 [2] de 17 [2] ca 0c [2] c5 16 [2] db 0b [2] d9 0a [2] c2 0c [2] de 0b [2] c2 24 }

  condition:
    any of them
}