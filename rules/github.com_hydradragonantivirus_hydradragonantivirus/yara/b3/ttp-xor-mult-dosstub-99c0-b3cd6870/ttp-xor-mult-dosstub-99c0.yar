rule TTP_XOR_MULT_DOSStub_99c0 {
  strings:
    $key_99c0 = { cd a8 [2] b9 b0 [2] fe b2 [2] b9 a3 [2] f7 af [2] fb a5 [2] ec ae [2] f7 e0 [2] ca }

  condition:
    any of them
}