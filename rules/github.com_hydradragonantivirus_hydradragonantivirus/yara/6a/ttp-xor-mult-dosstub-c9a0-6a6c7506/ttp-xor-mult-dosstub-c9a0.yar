rule TTP_XOR_MULT_DOSStub_c9a0 {
  strings:
    $key_c9a0 = { 9d c8 [2] e9 d0 [2] ae d2 [2] e9 c3 [2] a7 cf [2] ab c5 [2] bc ce [2] a7 80 [2] 9a }

  condition:
    any of them
}