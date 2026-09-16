rule TTP_XOR_QUAD_CurrentVersionRun_ac38 {
  strings:
    $key_ac38 = { ff 57 [2] db 59 [2] f0 75 [2] de 57 [2] ca 4c [2] c5 56 [2] db 4b [2] d9 4a [2] c2 4c [2] de 4b [2] c2 64 }

  condition:
    any of them
}