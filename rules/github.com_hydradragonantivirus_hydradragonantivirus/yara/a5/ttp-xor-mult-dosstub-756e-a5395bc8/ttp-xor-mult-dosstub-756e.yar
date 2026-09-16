rule TTP_XOR_MULT_DOSStub_756e {
  strings:
    $key_756e = { 21 06 [2] 55 1e [2] 12 1c [2] 55 0d [2] 1b 01 [2] 17 0b [2] 00 00 [2] 1b 4e [2] 26 }

  condition:
    any of them
}