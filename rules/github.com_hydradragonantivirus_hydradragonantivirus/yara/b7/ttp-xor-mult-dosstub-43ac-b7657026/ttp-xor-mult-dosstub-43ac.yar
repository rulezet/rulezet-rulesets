rule TTP_XOR_MULT_DOSStub_43ac {
  strings:
    $key_43ac = { 17 c4 [2] 63 dc [2] 24 de [2] 63 cf [2] 2d c3 [2] 21 c9 [2] 36 c2 [2] 2d 8c [2] 10 }

  condition:
    any of them
}