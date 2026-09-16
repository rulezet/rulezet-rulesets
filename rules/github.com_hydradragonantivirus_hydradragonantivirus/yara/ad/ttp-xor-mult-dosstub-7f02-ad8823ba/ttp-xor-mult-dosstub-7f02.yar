rule TTP_XOR_MULT_DOSStub_7f02 {
  strings:
    $key_7f02 = { 2b 6a [2] 5f 72 [2] 18 70 [2] 5f 61 [2] 11 6d [2] 1d 67 [2] 0a 6c [2] 11 22 [2] 2c }

  condition:
    any of them
}