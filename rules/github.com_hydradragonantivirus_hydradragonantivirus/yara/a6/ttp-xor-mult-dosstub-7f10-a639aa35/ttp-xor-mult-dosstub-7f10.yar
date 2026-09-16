rule TTP_XOR_MULT_DOSStub_7f10 {
  strings:
    $key_7f10 = { 2b 78 [2] 5f 60 [2] 18 62 [2] 5f 73 [2] 11 7f [2] 1d 75 [2] 0a 7e [2] 11 30 [2] 2c }

  condition:
    any of them
}