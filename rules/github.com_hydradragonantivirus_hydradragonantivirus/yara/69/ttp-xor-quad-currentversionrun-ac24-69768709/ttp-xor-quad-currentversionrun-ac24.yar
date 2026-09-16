rule TTP_XOR_QUAD_CurrentVersionRun_ac24 {
  strings:
    $key_ac24 = { ff 4b [2] db 45 [2] f0 69 [2] de 4b [2] ca 50 [2] c5 4a [2] db 57 [2] d9 56 [2] c2 50 [2] de 57 [2] c2 78 }

  condition:
    any of them
}