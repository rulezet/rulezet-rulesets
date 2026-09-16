rule TTP_XOR_MULT_DOSStub_d9c5 {
  strings:
    $key_d9c5 = { 8d ad [2] f9 b5 [2] be b7 [2] f9 a6 [2] b7 aa [2] bb a0 [2] ac ab [2] b7 e5 [2] 8a }

  condition:
    any of them
}