rule TTP_XOR_MULT_DOSStub_93c6 {
  strings:
    $key_93c6 = { c7 ae [2] b3 b6 [2] f4 b4 [2] b3 a5 [2] fd a9 [2] f1 a3 [2] e6 a8 [2] fd e6 [2] c0 }

  condition:
    any of them
}