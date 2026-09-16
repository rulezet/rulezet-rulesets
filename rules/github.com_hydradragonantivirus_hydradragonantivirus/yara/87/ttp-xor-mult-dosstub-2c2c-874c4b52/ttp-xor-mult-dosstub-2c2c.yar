rule TTP_XOR_MULT_DOSStub_2c2c {
  strings:
    $key_2c2c = { 78 44 [2] 0c 5c [2] 4b 5e [2] 0c 4f [2] 42 43 [2] 4e 49 [2] 59 42 [2] 42 0c [2] 7f }

  condition:
    any of them
}