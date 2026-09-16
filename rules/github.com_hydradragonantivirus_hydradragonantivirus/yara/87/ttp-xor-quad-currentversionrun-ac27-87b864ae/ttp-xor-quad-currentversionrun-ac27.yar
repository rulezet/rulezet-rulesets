rule TTP_XOR_QUAD_CurrentVersionRun_ac27 {
  strings:
    $key_ac27 = { ff 48 [2] db 46 [2] f0 6a [2] de 48 [2] ca 53 [2] c5 49 [2] db 54 [2] d9 55 [2] c2 53 [2] de 54 [2] c2 7b }

  condition:
    any of them
}