rule TTP_XOR_MULT_DOSStub_aec1 {
  strings:
    $key_aec1 = { fa a9 [2] 8e b1 [2] c9 b3 [2] 8e a2 [2] c0 ae [2] cc a4 [2] db af [2] c0 e1 [2] fd }

  condition:
    any of them
}