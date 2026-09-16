rule TTP_XOR_MULT_DOSStub_7f23 {
  strings:
    $key_7f23 = { 2b 4b [2] 5f 53 [2] 18 51 [2] 5f 40 [2] 11 4c [2] 1d 46 [2] 0a 4d [2] 11 03 [2] 2c }

  condition:
    any of them
}