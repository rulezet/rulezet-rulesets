rule TTP_XOR_MULT_DOSStub_2c7c {
  strings:
    $key_2c7c = { 78 14 [2] 0c 0c [2] 4b 0e [2] 0c 1f [2] 42 13 [2] 4e 19 [2] 59 12 [2] 42 5c [2] 7f }

  condition:
    any of them
}