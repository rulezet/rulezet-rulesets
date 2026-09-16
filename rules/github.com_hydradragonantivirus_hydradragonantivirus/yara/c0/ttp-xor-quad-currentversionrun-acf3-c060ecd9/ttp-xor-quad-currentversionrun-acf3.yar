rule TTP_XOR_QUAD_CurrentVersionRun_acf3 {
  strings:
    $key_acf3 = { ff 9c [2] db 92 [2] f0 be [2] de 9c [2] ca 87 [2] c5 9d [2] db 80 [2] d9 81 [2] c2 87 [2] de 80 [2] c2 af }

  condition:
    any of them
}