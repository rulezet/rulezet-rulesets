rule TTP_XOR_MULT_DOSStub_c914 {
  strings:
    $key_c914 = { 9d 7c [2] e9 64 [2] ae 66 [2] e9 77 [2] a7 7b [2] ab 71 [2] bc 7a [2] a7 34 [2] 9a }

  condition:
    any of them
}