rule TTP_XOR_MULT_DOSStub_c939 {
  strings:
    $key_c939 = { 9d 51 [2] e9 49 [2] ae 4b [2] e9 5a [2] a7 56 [2] ab 5c [2] bc 57 [2] a7 19 [2] 9a }

  condition:
    any of them
}