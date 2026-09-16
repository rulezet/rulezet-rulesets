rule TTP_XOR_MULT_DOSStub_7e7e {
  strings:
    $key_7e7e = { 2a 16 [2] 5e 0e [2] 19 0c [2] 5e 1d [2] 10 11 [2] 1c 1b [2] 0b 10 [2] 10 5e [2] 2d }

  condition:
    any of them
}