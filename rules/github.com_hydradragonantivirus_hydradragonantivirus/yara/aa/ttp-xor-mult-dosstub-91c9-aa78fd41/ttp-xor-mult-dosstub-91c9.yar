rule TTP_XOR_MULT_DOSStub_91c9 {
  strings:
    $key_91c9 = { c5 a1 [2] b1 b9 [2] f6 bb [2] b1 aa [2] ff a6 [2] f3 ac [2] e4 a7 [2] ff e9 [2] c2 }

  condition:
    any of them
}