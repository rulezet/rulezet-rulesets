rule TTP_XOR_QUAD_CurrentVersionRun_ac35 {
  strings:
    $key_ac35 = { ff 5a [2] db 54 [2] f0 78 [2] de 5a [2] ca 41 [2] c5 5b [2] db 46 [2] d9 47 [2] c2 41 [2] de 46 [2] c2 69 }

  condition:
    any of them
}