rule TTP_XOR_MULT_DOSStub_d59c {
  strings:
    $key_d59c = { 81 f4 [2] f5 ec [2] b2 ee [2] f5 ff [2] bb f3 [2] b7 f9 [2] a0 f2 [2] bb bc [2] 86 }

  condition:
    any of them
}