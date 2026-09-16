rule TTP_XOR_MULT_DOSStub_c929 {
  strings:
    $key_c929 = { 9d 41 [2] e9 59 [2] ae 5b [2] e9 4a [2] a7 46 [2] ab 4c [2] bc 47 [2] a7 09 [2] 9a }

  condition:
    any of them
}