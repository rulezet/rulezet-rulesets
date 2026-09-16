rule TTP_XOR_MULT_DOSStub_91ac {
  strings:
    $key_91ac = { c5 c4 [2] b1 dc [2] f6 de [2] b1 cf [2] ff c3 [2] f3 c9 [2] e4 c2 [2] ff 8c [2] c2 }

  condition:
    any of them
}