rule TTP_XOR_MULT_DOSStub_2c4c {
  strings:
    $key_2c4c = { 78 24 [2] 0c 3c [2] 4b 3e [2] 0c 2f [2] 42 23 [2] 4e 29 [2] 59 22 [2] 42 6c [2] 7f }

  condition:
    any of them
}