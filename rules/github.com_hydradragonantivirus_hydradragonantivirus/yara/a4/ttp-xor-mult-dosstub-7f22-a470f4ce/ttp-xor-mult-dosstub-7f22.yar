rule TTP_XOR_MULT_DOSStub_7f22 {
  strings:
    $key_7f22 = { 2b 4a [2] 5f 52 [2] 18 50 [2] 5f 41 [2] 11 4d [2] 1d 47 [2] 0a 4c [2] 11 02 [2] 2c }

  condition:
    any of them
}