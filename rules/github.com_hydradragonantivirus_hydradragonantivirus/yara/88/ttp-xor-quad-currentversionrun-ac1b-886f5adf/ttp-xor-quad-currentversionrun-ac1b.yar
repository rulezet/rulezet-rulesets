rule TTP_XOR_QUAD_CurrentVersionRun_ac1b {
  strings:
    $key_ac1b = { ff 74 [2] db 7a [2] f0 56 [2] de 74 [2] ca 6f [2] c5 75 [2] db 68 [2] d9 69 [2] c2 6f [2] de 68 [2] c2 47 }

  condition:
    any of them
}