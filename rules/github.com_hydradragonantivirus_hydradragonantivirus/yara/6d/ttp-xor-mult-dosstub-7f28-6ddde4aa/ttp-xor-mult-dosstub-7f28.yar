rule TTP_XOR_MULT_DOSStub_7f28 {
  strings:
    $key_7f28 = { 2b 40 [2] 5f 58 [2] 18 5a [2] 5f 4b [2] 11 47 [2] 1d 4d [2] 0a 46 [2] 11 08 [2] 2c }

  condition:
    any of them
}