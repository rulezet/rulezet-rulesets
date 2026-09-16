rule TTP_XOR_QUAD_CurrentVersionRun_ac05 {
  strings:
    $key_ac05 = { ff 6a [2] db 64 [2] f0 48 [2] de 6a [2] ca 71 [2] c5 6b [2] db 76 [2] d9 77 [2] c2 71 [2] de 76 [2] c2 59 }

  condition:
    any of them
}