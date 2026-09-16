rule TTP_XOR_MULT_DOSStub_c935 {
  strings:
    $key_c935 = { 9d 5d [2] e9 45 [2] ae 47 [2] e9 56 [2] a7 5a [2] ab 50 [2] bc 5b [2] a7 15 [2] 9a }

  condition:
    any of them
}