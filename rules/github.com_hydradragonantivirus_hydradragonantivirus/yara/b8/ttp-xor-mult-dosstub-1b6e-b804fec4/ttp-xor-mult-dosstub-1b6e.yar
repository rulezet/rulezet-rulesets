rule TTP_XOR_MULT_DOSStub_1b6e {
  strings:
    $key_1b6e = { 4f 06 [2] 3b 1e [2] 7c 1c [2] 3b 0d [2] 75 01 [2] 79 0b [2] 6e 00 [2] 75 4e [2] 48 }

  condition:
    any of them
}