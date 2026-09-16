rule TTP_XOR_MULT_DOSStub_369a {
  strings:
    $key_369a = { 62 f2 [2] 16 ea [2] 51 e8 [2] 16 f9 [2] 58 f5 [2] 54 ff [2] 43 f4 [2] 58 ba [2] 65 }

  condition:
    any of them
}