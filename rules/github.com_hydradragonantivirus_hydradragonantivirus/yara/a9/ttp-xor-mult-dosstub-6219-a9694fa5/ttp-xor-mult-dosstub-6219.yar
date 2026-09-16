rule TTP_XOR_MULT_DOSStub_6219 {
  strings:
    $key_6219 = { 36 71 [2] 42 69 [2] 05 6b [2] 42 7a [2] 0c 76 [2] 00 7c [2] 17 77 [2] 0c 39 [2] 31 }

  condition:
    any of them
}