rule TTP_XOR_QUAD_CurrentVersionRun_ac33 {
  strings:
    $key_ac33 = { ff 5c [2] db 52 [2] f0 7e [2] de 5c [2] ca 47 [2] c5 5d [2] db 40 [2] d9 41 [2] c2 47 [2] de 40 [2] c2 6f }

  condition:
    any of them
}