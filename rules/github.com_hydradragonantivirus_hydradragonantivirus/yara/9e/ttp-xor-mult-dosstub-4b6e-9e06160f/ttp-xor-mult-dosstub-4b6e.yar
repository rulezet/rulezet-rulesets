rule TTP_XOR_MULT_DOSStub_4b6e {
  strings:
    $key_4b6e = { 1f 06 [2] 6b 1e [2] 2c 1c [2] 6b 0d [2] 25 01 [2] 29 0b [2] 3e 00 [2] 25 4e [2] 18 }

  condition:
    any of them
}