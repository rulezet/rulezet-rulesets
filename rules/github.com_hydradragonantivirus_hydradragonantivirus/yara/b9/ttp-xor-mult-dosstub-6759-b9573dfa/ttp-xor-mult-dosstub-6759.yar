rule TTP_XOR_MULT_DOSStub_6759 {
  strings:
    $key_6759 = { 33 31 [2] 47 29 [2] 00 2b [2] 47 3a [2] 09 36 [2] 05 3c [2] 12 37 [2] 09 79 [2] 34 }

  condition:
    any of them
}