rule TTP_XOR_MULT_DOSStub_d7cb {
  strings:
    $key_d7cb = { 83 a3 [2] f7 bb [2] b0 b9 [2] f7 a8 [2] b9 a4 [2] b5 ae [2] a2 a5 [2] b9 eb [2] 84 }

  condition:
    any of them
}