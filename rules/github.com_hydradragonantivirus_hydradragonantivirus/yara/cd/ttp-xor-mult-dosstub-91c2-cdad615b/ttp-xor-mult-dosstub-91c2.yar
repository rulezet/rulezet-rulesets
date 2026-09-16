rule TTP_XOR_MULT_DOSStub_91c2 {
  strings:
    $key_91c2 = { c5 aa [2] b1 b2 [2] f6 b0 [2] b1 a1 [2] ff ad [2] f3 a7 [2] e4 ac [2] ff e2 [2] c2 }

  condition:
    any of them
}