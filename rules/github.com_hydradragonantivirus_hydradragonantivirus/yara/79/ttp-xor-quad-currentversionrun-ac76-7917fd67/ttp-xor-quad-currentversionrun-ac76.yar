rule TTP_XOR_QUAD_CurrentVersionRun_ac76 {
  strings:
    $key_ac76 = { ff 19 [2] db 17 [2] f0 3b [2] de 19 [2] ca 02 [2] c5 18 [2] db 05 [2] d9 04 [2] c2 02 [2] de 05 [2] c2 2a }

  condition:
    any of them
}