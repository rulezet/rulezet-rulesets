rule TTP_XOR_QUAD_CurrentVersionRun_ac0c {
  strings:
    $key_ac0c = { ff 63 [2] db 6d [2] f0 41 [2] de 63 [2] ca 78 [2] c5 62 [2] db 7f [2] d9 7e [2] c2 78 [2] de 7f [2] c2 50 }

  condition:
    any of them
}