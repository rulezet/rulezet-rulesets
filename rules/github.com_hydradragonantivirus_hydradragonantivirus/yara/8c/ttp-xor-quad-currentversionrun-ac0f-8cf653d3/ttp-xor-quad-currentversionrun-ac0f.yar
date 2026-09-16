rule TTP_XOR_QUAD_CurrentVersionRun_ac0f {
  strings:
    $key_ac0f = { ff 60 [2] db 6e [2] f0 42 [2] de 60 [2] ca 7b [2] c5 61 [2] db 7c [2] d9 7d [2] c2 7b [2] de 7c [2] c2 53 }

  condition:
    any of them
}