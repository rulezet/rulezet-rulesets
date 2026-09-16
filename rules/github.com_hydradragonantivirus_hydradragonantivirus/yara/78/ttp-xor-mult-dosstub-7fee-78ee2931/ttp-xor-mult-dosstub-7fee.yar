rule TTP_XOR_MULT_DOSStub_7fee {
  strings:
    $key_7fee = { 2b 86 [2] 5f 9e [2] 18 9c [2] 5f 8d [2] 11 81 [2] 1d 8b [2] 0a 80 [2] 11 ce [2] 2c }

  condition:
    any of them
}