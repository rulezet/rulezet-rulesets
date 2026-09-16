rule TTP_XOR_QUAD_CurrentVersionRun_ac48 {
  strings:
    $key_ac48 = { ff 27 [2] db 29 [2] f0 05 [2] de 27 [2] ca 3c [2] c5 26 [2] db 3b [2] d9 3a [2] c2 3c [2] de 3b [2] c2 14 }

  condition:
    any of them
}