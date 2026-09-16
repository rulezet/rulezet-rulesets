rule TTP_XOR_MULT_DOSStub_766e {
  strings:
    $key_766e = { 22 06 [2] 56 1e [2] 11 1c [2] 56 0d [2] 18 01 [2] 14 0b [2] 03 00 [2] 18 4e [2] 25 }

  condition:
    any of them
}