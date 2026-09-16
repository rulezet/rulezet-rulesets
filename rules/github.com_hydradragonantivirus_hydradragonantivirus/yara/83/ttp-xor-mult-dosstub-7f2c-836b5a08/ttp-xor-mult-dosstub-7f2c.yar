rule TTP_XOR_MULT_DOSStub_7f2c {
  strings:
    $key_7f2c = { 2b 44 [2] 5f 5c [2] 18 5e [2] 5f 4f [2] 11 43 [2] 1d 49 [2] 0a 42 [2] 11 0c [2] 2c }

  condition:
    any of them
}