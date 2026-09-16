rule TTP_XOR_MULT_DOSStub_93c4 {
  strings:
    $key_93c4 = { c7 ac [2] b3 b4 [2] f4 b6 [2] b3 a7 [2] fd ab [2] f1 a1 [2] e6 aa [2] fd e4 [2] c0 }

  condition:
    any of them
}