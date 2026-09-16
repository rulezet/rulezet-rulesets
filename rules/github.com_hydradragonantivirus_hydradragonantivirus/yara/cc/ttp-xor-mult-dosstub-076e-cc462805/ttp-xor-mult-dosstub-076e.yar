rule TTP_XOR_MULT_DOSStub_076e {
  strings:
    $key_076e = { 53 06 [2] 27 1e [2] 60 1c [2] 27 0d [2] 69 01 [2] 65 0b [2] 72 00 [2] 69 4e [2] 54 }

  condition:
    any of them
}