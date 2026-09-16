rule TTP_XOR_MULT_DOSStub_4b7e {
  strings:
    $key_4b7e = { 1f 16 [2] 6b 0e [2] 2c 0c [2] 6b 1d [2] 25 11 [2] 29 1b [2] 3e 10 [2] 25 5e [2] 18 }

  condition:
    any of them
}