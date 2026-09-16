rule TTP_XOR_QUAD_CurrentVersionRun_ac39 {
  strings:
    $key_ac39 = { ff 56 [2] db 58 [2] f0 74 [2] de 56 [2] ca 4d [2] c5 57 [2] db 4a [2] d9 4b [2] c2 4d [2] de 4a [2] c2 65 }

  condition:
    any of them
}