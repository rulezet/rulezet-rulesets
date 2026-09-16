rule TTP_XOR_MULT_DOSStub_c9ac {
  strings:
    $key_c9ac = { 9d c4 [2] e9 dc [2] ae de [2] e9 cf [2] a7 c3 [2] ab c9 [2] bc c2 [2] a7 8c [2] 9a }

  condition:
    any of them
}