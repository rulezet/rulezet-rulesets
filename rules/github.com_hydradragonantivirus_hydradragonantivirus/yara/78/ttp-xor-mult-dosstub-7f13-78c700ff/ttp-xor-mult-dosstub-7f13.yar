rule TTP_XOR_MULT_DOSStub_7f13 {
  strings:
    $key_7f13 = { 2b 7b [2] 5f 63 [2] 18 61 [2] 5f 70 [2] 11 7c [2] 1d 76 [2] 0a 7d [2] 11 33 [2] 2c }

  condition:
    any of them
}