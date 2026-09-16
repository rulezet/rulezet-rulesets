rule TTP_XOR_MULT_DOSStub_c908 {
  strings:
    $key_c908 = { 9d 60 [2] e9 78 [2] ae 7a [2] e9 6b [2] a7 67 [2] ab 6d [2] bc 66 [2] a7 28 [2] 9a }

  condition:
    any of them
}