rule TTP_XOR_MULT_DOSStub_8bca {
  strings:
    $key_8bca = { df a2 [2] ab ba [2] ec b8 [2] ab a9 [2] e5 a5 [2] e9 af [2] fe a4 [2] e5 ea [2] d8 }

  condition:
    any of them
}