rule TTP_XOR_QUAD_CurrentVersionRun_ace4 {
  strings:
    $key_ace4 = { ff 8b [2] db 85 [2] f0 a9 [2] de 8b [2] ca 90 [2] c5 8a [2] db 97 [2] d9 96 [2] c2 90 [2] de 97 [2] c2 b8 }

  condition:
    any of them
}