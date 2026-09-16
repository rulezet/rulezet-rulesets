rule TTP_XOR_MULT_DOSStub_7f25 {
  strings:
    $key_7f25 = { 2b 4d [2] 5f 55 [2] 18 57 [2] 5f 46 [2] 11 4a [2] 1d 40 [2] 0a 4b [2] 11 05 [2] 2c }

  condition:
    any of them
}