rule TTP_XOR_MULT_DOSStub_99c2 {
  strings:
    $key_99c2 = { cd aa [2] b9 b2 [2] fe b0 [2] b9 a1 [2] f7 ad [2] fb a7 [2] ec ac [2] f7 e2 [2] ca }

  condition:
    any of them
}