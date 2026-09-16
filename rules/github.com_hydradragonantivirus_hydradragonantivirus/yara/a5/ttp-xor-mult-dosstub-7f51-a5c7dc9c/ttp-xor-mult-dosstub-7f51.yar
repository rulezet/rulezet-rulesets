rule TTP_XOR_MULT_DOSStub_7f51 {
  strings:
    $key_7f51 = { 2b 39 [2] 5f 21 [2] 18 23 [2] 5f 32 [2] 11 3e [2] 1d 34 [2] 0a 3f [2] 11 71 [2] 2c }

  condition:
    any of them
}