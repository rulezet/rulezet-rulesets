rule TTP_XOR_MULT_DOSStub_e9c5 {
  strings:
    $key_e9c5 = { bd ad [2] c9 b5 [2] 8e b7 [2] c9 a6 [2] 87 aa [2] 8b a0 [2] 9c ab [2] 87 e5 [2] ba }

  condition:
    any of them
}