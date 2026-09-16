rule TTP_XOR_MULT_DOSStub_7e6e {
  strings:
    $key_7e6e = { 2a 06 [2] 5e 1e [2] 19 1c [2] 5e 0d [2] 10 01 [2] 1c 0b [2] 0b 00 [2] 10 4e [2] 2d }

  condition:
    any of them
}