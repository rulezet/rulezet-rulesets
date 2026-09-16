rule TTP_XOR_MULT_DOSStub_4f5c {
  strings:
    $key_4f5c = { 1b 34 [2] 6f 2c [2] 28 2e [2] 6f 3f [2] 21 33 [2] 2d 39 [2] 3a 32 [2] 21 7c [2] 1c }

  condition:
    any of them
}