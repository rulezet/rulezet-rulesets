rule TTP_XOR_MULT_DOSStub_2c6e {
  strings:
    $key_2c6e = { 78 06 [2] 0c 1e [2] 4b 1c [2] 0c 0d [2] 42 01 [2] 4e 0b [2] 59 00 [2] 42 4e [2] 7f }

  condition:
    any of them
}