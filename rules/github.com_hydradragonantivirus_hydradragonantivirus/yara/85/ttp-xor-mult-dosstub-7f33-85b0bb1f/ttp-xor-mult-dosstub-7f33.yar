rule TTP_XOR_MULT_DOSStub_7f33 {
  strings:
    $key_7f33 = { 2b 5b [2] 5f 43 [2] 18 41 [2] 5f 50 [2] 11 5c [2] 1d 56 [2] 0a 5d [2] 11 13 [2] 2c }

  condition:
    any of them
}