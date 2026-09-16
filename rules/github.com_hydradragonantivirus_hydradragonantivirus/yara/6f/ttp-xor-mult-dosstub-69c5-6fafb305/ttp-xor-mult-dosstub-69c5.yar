rule TTP_XOR_MULT_DOSStub_69c5 {
  strings:
    $key_69c5 = { 3d ad [2] 49 b5 [2] 0e b7 [2] 49 a6 [2] 07 aa [2] 0b a0 [2] 1c ab [2] 07 e5 [2] 3a }

  condition:
    any of them
}