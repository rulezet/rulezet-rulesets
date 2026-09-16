rule TTP_XOR_MULT_DOSStub_369e {
  strings:
    $key_369e = { 62 f6 [2] 16 ee [2] 51 ec [2] 16 fd [2] 58 f1 [2] 54 fb [2] 43 f0 [2] 58 be [2] 65 }

  condition:
    any of them
}