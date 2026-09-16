rule TTP_XOR_MULT_DOSStub_7f18 {
  strings:
    $key_7f18 = { 2b 70 [2] 5f 68 [2] 18 6a [2] 5f 7b [2] 11 77 [2] 1d 7d [2] 0a 76 [2] 11 38 [2] 2c }

  condition:
    any of them
}