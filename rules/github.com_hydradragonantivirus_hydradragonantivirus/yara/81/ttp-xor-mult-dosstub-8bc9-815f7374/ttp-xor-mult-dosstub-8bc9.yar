rule TTP_XOR_MULT_DOSStub_8bc9 {
  strings:
    $key_8bc9 = { df a1 [2] ab b9 [2] ec bb [2] ab aa [2] e5 a6 [2] e9 ac [2] fe a7 [2] e5 e9 [2] d8 }

  condition:
    any of them
}