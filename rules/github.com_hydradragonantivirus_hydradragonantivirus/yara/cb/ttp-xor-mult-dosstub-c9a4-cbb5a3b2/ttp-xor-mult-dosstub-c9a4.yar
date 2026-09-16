rule TTP_XOR_MULT_DOSStub_c9a4 {
  strings:
    $key_c9a4 = { 9d cc [2] e9 d4 [2] ae d6 [2] e9 c7 [2] a7 cb [2] ab c1 [2] bc ca [2] a7 84 [2] 9a }

  condition:
    any of them
}