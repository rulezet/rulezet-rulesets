rule TTP_XOR_MULT_DOSStub_476e {
  strings:
    $key_476e = { 13 06 [2] 67 1e [2] 20 1c [2] 67 0d [2] 29 01 [2] 25 0b [2] 32 00 [2] 29 4e [2] 14 }

  condition:
    any of them
}