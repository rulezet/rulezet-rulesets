rule TTP_XOR_MULT_DOSStub_a8c7 {
  strings:
    $key_a8c7 = { fc af [2] 88 b7 [2] cf b5 [2] 88 a4 [2] c6 a8 [2] ca a2 [2] dd a9 [2] c6 e7 [2] fb }

  condition:
    any of them
}