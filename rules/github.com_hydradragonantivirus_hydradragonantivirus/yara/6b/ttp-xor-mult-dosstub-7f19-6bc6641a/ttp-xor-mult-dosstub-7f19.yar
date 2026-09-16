rule TTP_XOR_MULT_DOSStub_7f19 {
  strings:
    $key_7f19 = { 2b 71 [2] 5f 69 [2] 18 6b [2] 5f 7a [2] 11 76 [2] 1d 7c [2] 0a 77 [2] 11 39 [2] 2c }

  condition:
    any of them
}