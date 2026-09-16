rule TTP_XOR_MULT_DOSStub_6f5c {
  strings:
    $key_6f5c = { 3b 34 [2] 4f 2c [2] 08 2e [2] 4f 3f [2] 01 33 [2] 0d 39 [2] 1a 32 [2] 01 7c [2] 3c }

  condition:
    any of them
}