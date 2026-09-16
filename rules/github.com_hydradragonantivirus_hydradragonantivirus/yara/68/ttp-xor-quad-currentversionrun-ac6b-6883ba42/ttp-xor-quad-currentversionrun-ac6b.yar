rule TTP_XOR_QUAD_CurrentVersionRun_ac6b {
  strings:
    $key_ac6b = { ff 04 [2] db 0a [2] f0 26 [2] de 04 [2] ca 1f [2] c5 05 [2] db 18 [2] d9 19 [2] c2 1f [2] de 18 [2] c2 37 }

  condition:
    any of them
}