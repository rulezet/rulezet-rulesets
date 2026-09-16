rule TTP_XOR_QUAD_CurrentVersionRun_acef {
  strings:
    $key_acef = { ff 80 [2] db 8e [2] f0 a2 [2] de 80 [2] ca 9b [2] c5 81 [2] db 9c [2] d9 9d [2] c2 9b [2] de 9c [2] c2 b3 }

  condition:
    any of them
}