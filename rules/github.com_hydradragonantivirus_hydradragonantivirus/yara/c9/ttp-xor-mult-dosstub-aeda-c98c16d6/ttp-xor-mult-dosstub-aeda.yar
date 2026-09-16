rule TTP_XOR_MULT_DOSStub_aeda {
  strings:
    $key_aeda = { fa b2 [2] 8e aa [2] c9 a8 [2] 8e b9 [2] c0 b5 [2] cc bf [2] db b4 [2] c0 fa [2] fd }

  condition:
    any of them
}