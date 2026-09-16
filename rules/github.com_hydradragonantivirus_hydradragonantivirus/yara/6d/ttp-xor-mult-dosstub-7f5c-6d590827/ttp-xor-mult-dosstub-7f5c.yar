rule TTP_XOR_MULT_DOSStub_7f5c {
  strings:
    $key_7f5c = { 2b 34 [2] 5f 2c [2] 18 2e [2] 5f 3f [2] 11 33 [2] 1d 39 [2] 0a 32 [2] 11 7c [2] 2c }

  condition:
    any of them
}