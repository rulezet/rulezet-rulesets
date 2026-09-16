rule TTP_XOR_MULT_DOSStub_aec8 {
  strings:
    $key_aec8 = { fa a0 [2] 8e b8 [2] c9 ba [2] 8e ab [2] c0 a7 [2] cc ad [2] db a6 [2] c0 e8 [2] fd }

  condition:
    any of them
}