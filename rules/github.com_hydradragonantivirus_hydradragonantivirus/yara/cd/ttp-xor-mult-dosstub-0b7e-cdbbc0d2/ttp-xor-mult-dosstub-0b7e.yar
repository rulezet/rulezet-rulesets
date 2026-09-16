rule TTP_XOR_MULT_DOSStub_0b7e {
  strings:
    $key_0b7e = { 5f 16 [2] 2b 0e [2] 6c 0c [2] 2b 1d [2] 65 11 [2] 69 1b [2] 7e 10 [2] 65 5e [2] 58 }

  condition:
    any of them
}