rule TTP_XOR_MULT_DOSStub_7f1b {
  strings:
    $key_7f1b = { 2b 73 [2] 5f 6b [2] 18 69 [2] 5f 78 [2] 11 74 [2] 1d 7e [2] 0a 75 [2] 11 3b [2] 2c }

  condition:
    any of them
}