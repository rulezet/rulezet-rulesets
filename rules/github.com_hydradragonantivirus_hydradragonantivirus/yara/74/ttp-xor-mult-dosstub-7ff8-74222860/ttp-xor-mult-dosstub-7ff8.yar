rule TTP_XOR_MULT_DOSStub_7ff8 {
  strings:
    $key_7ff8 = { 2b 90 [2] 5f 88 [2] 18 8a [2] 5f 9b [2] 11 97 [2] 1d 9d [2] 0a 96 [2] 11 d8 [2] 2c }

  condition:
    any of them
}