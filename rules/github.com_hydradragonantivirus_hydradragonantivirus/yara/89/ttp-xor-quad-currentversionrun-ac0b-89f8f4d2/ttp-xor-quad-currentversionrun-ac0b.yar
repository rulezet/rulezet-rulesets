rule TTP_XOR_QUAD_CurrentVersionRun_ac0b {
  strings:
    $key_ac0b = { ff 64 [2] db 6a [2] f0 46 [2] de 64 [2] ca 7f [2] c5 65 [2] db 78 [2] d9 79 [2] c2 7f [2] de 78 [2] c2 57 }

  condition:
    any of them
}