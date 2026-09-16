rule TTP_XOR_MULT_DOSStub_93c5 {
  strings:
    $key_93c5 = { c7 ad [2] b3 b5 [2] f4 b7 [2] b3 a6 [2] fd aa [2] f1 a0 [2] e6 ab [2] fd e5 [2] c0 }

  condition:
    any of them
}