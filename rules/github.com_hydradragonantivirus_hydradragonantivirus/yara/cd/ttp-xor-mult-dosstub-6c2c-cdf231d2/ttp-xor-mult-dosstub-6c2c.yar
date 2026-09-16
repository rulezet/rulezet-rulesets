rule TTP_XOR_MULT_DOSStub_6c2c {
  strings:
    $key_6c2c = { 38 44 [2] 4c 5c [2] 0b 5e [2] 4c 4f [2] 02 43 [2] 0e 49 [2] 19 42 [2] 02 0c [2] 3f }

  condition:
    any of them
}