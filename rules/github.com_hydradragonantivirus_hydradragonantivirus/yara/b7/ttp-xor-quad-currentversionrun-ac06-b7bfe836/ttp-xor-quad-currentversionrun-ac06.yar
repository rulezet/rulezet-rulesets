rule TTP_XOR_QUAD_CurrentVersionRun_ac06 {
  strings:
    $key_ac06 = { ff 69 [2] db 67 [2] f0 4b [2] de 69 [2] ca 72 [2] c5 68 [2] db 75 [2] d9 74 [2] c2 72 [2] de 75 [2] c2 5a }

  condition:
    any of them
}