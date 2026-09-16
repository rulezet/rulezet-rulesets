rule TTP_XOR_MULT_DOSStub_4d6e {
  strings:
    $key_4d6e = { 19 06 [2] 6d 1e [2] 2a 1c [2] 6d 0d [2] 23 01 [2] 2f 0b [2] 38 00 [2] 23 4e [2] 1e }

  condition:
    any of them
}