rule TTP_XOR_QUAD_CurrentVersionRun_ac29 {
  strings:
    $key_ac29 = { ff 46 [2] db 48 [2] f0 64 [2] de 46 [2] ca 5d [2] c5 47 [2] db 5a [2] d9 5b [2] c2 5d [2] de 5a [2] c2 75 }

  condition:
    any of them
}