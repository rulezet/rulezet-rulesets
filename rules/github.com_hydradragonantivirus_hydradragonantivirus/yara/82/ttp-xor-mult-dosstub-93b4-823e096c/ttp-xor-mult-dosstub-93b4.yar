rule TTP_XOR_MULT_DOSStub_93b4 {
  strings:
    $key_93b4 = { c7 dc [2] b3 c4 [2] f4 c6 [2] b3 d7 [2] fd db [2] f1 d1 [2] e6 da [2] fd 94 [2] c0 }

  condition:
    any of them
}