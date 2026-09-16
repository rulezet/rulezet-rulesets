rule TTP_XOR_QUAD_CurrentVersionRun_ac07 {
  strings:
    $key_ac07 = { ff 68 [2] db 66 [2] f0 4a [2] de 68 [2] ca 73 [2] c5 69 [2] db 74 [2] d9 75 [2] c2 73 [2] de 74 [2] c2 5b }

  condition:
    any of them
}