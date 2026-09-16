rule TTP_XOR_MULT_DOSStub_c9a2 {
  strings:
    $key_c9a2 = { 9d ca [2] e9 d2 [2] ae d0 [2] e9 c1 [2] a7 cd [2] ab c7 [2] bc cc [2] a7 82 [2] 9a }

  condition:
    any of them
}