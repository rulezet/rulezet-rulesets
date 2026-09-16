rule TTP_XOR_QUAD_CurrentVersionRun_ace5 {
  strings:
    $key_ace5 = { ff 8a [2] db 84 [2] f0 a8 [2] de 8a [2] ca 91 [2] c5 8b [2] db 96 [2] d9 97 [2] c2 91 [2] de 96 [2] c2 b9 }

  condition:
    any of them
}