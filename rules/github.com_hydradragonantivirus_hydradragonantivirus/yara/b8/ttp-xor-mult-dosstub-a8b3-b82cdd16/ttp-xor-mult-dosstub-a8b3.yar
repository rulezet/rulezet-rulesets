rule TTP_XOR_MULT_DOSStub_a8b3 {
  strings:
    $key_a8b3 = { fc db [2] 88 c3 [2] cf c1 [2] 88 d0 [2] c6 dc [2] ca d6 [2] dd dd [2] c6 93 [2] fb }

  condition:
    any of them
}