rule TTP_XOR_MULT_DOSStub_6014 {
  strings:
    $key_6014 = { 34 7c [2] 40 64 [2] 07 66 [2] 40 77 [2] 0e 7b [2] 02 71 [2] 15 7a [2] 0e 34 [2] 33 }

  condition:
    any of them
}