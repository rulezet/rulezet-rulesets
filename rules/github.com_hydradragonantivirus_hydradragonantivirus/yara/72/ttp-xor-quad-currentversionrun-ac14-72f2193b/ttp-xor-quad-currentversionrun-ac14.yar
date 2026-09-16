rule TTP_XOR_QUAD_CurrentVersionRun_ac14 {
  strings:
    $key_ac14 = { ff 7b [2] db 75 [2] f0 59 [2] de 7b [2] ca 60 [2] c5 7a [2] db 67 [2] d9 66 [2] c2 60 [2] de 67 [2] c2 48 }

  condition:
    any of them
}