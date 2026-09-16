rule TTP_XOR_MULT_DOSStub_4f2c {
  strings:
    $key_4f2c = { 1b 44 [2] 6f 5c [2] 28 5e [2] 6f 4f [2] 21 43 [2] 2d 49 [2] 3a 42 [2] 21 0c [2] 1c }

  condition:
    any of them
}