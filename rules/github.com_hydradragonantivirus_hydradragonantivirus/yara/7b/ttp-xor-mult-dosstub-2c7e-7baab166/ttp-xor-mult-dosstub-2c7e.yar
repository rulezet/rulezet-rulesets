rule TTP_XOR_MULT_DOSStub_2c7e {
  strings:
    $key_2c7e = { 78 16 [2] 0c 0e [2] 4b 0c [2] 0c 1d [2] 42 11 [2] 4e 1b [2] 59 10 [2] 42 5e [2] 7f }

  condition:
    any of them
}