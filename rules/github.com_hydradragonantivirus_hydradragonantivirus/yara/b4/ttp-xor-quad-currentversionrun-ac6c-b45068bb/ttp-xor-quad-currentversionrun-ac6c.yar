rule TTP_XOR_QUAD_CurrentVersionRun_ac6c {
  strings:
    $key_ac6c = { ff 03 [2] db 0d [2] f0 21 [2] de 03 [2] ca 18 [2] c5 02 [2] db 1f [2] d9 1e [2] c2 18 [2] de 1f [2] c2 30 }

  condition:
    any of them
}