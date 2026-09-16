rule TTP_XOR_MULT_DOSStub_93c0 {
  strings:
    $key_93c0 = { c7 a8 [2] b3 b0 [2] f4 b2 [2] b3 a3 [2] fd af [2] f1 a5 [2] e6 ae [2] fd e0 [2] c0 }

  condition:
    any of them
}