rule TTP_XOR_MULT_DOSStub_7f39 {
  strings:
    $key_7f39 = { 2b 51 [2] 5f 49 [2] 18 4b [2] 5f 5a [2] 11 56 [2] 1d 5c [2] 0a 57 [2] 11 19 [2] 2c }

  condition:
    any of them
}