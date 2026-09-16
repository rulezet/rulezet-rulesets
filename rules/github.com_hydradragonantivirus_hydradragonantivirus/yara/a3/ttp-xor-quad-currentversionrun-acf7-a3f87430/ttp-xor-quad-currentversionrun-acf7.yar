rule TTP_XOR_QUAD_CurrentVersionRun_acf7 {
  strings:
    $key_acf7 = { ff 98 [2] db 96 [2] f0 ba [2] de 98 [2] ca 83 [2] c5 99 [2] db 84 [2] d9 85 [2] c2 83 [2] de 84 [2] c2 ab }

  condition:
    any of them
}