rule TTP_XOR_MULT_DOSStub_781c {
  strings:
    $key_781c = { 2c 74 [2] 58 6c [2] 1f 6e [2] 58 7f [2] 16 73 [2] 1a 79 [2] 0d 72 [2] 16 3c [2] 2b }

  condition:
    any of them
}