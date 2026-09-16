rule TTP_XOR_QUAD_CurrentVersionRun_ac17 {
  strings:
    $key_ac17 = { ff 78 [2] db 76 [2] f0 5a [2] de 78 [2] ca 63 [2] c5 79 [2] db 64 [2] d9 65 [2] c2 63 [2] de 64 [2] c2 4b }

  condition:
    any of them
}