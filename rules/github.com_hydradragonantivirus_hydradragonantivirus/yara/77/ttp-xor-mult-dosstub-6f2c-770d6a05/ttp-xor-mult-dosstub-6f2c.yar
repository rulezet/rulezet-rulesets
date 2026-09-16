rule TTP_XOR_MULT_DOSStub_6f2c {
  strings:
    $key_6f2c = { 3b 44 [2] 4f 5c [2] 08 5e [2] 4f 4f [2] 01 43 [2] 0d 49 [2] 1a 42 [2] 01 0c [2] 3c }

  condition:
    any of them
}