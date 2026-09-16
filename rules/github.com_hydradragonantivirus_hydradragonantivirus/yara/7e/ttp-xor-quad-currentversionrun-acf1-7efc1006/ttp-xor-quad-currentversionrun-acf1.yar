rule TTP_XOR_QUAD_CurrentVersionRun_acf1 {
  strings:
    $key_acf1 = { ff 9e [2] db 90 [2] f0 bc [2] de 9e [2] ca 85 [2] c5 9f [2] db 82 [2] d9 83 [2] c2 85 [2] de 82 [2] c2 ad }

  condition:
    any of them
}