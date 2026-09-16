rule TTP_XOR_MULT_DOSStub_7f34 {
  strings:
    $key_7f34 = { 2b 5c [2] 5f 44 [2] 18 46 [2] 5f 57 [2] 11 5b [2] 1d 51 [2] 0a 5a [2] 11 14 [2] 2c }

  condition:
    any of them
}