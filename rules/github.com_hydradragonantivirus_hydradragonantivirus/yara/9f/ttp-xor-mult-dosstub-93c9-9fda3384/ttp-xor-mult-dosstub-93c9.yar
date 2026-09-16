rule TTP_XOR_MULT_DOSStub_93c9 {
  strings:
    $key_93c9 = { c7 a1 [2] b3 b9 [2] f4 bb [2] b3 aa [2] fd a6 [2] f1 ac [2] e6 a7 [2] fd e9 [2] c0 }

  condition:
    any of them
}