rule TTP_XOR_MULT_DOSStub_6c7e {
  strings:
    $key_6c7e = { 38 16 [2] 4c 0e [2] 0b 0c [2] 4c 1d [2] 02 11 [2] 0e 1b [2] 19 10 [2] 02 5e [2] 3f }

  condition:
    any of them
}