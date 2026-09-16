rule TTP_XOR_MULT_DOSStub_7b2c {
  strings:
    $key_7b2c = { 2f 44 [2] 5b 5c [2] 1c 5e [2] 5b 4f [2] 15 43 [2] 19 49 [2] 0e 42 [2] 15 0c [2] 28 }

  condition:
    any of them
}