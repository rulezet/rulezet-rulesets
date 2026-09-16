rule TTP_XOR_QUAD_CurrentVersionRun_ac0e {
  strings:
    $key_ac0e = { ff 61 [2] db 6f [2] f0 43 [2] de 61 [2] ca 7a [2] c5 60 [2] db 7d [2] d9 7c [2] c2 7a [2] de 7d [2] c2 52 }

  condition:
    any of them
}