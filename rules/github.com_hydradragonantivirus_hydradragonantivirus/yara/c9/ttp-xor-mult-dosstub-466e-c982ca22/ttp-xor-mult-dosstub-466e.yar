rule TTP_XOR_MULT_DOSStub_466e {
  strings:
    $key_466e = { 12 06 [2] 66 1e [2] 21 1c [2] 66 0d [2] 28 01 [2] 24 0b [2] 33 00 [2] 28 4e [2] 15 }

  condition:
    any of them
}