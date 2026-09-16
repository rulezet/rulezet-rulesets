rule TTP_XOR_MULT_DOSStub_456e {
  strings:
    $key_456e = { 11 06 [2] 65 1e [2] 22 1c [2] 65 0d [2] 2b 01 [2] 27 0b [2] 30 00 [2] 2b 4e [2] 16 }

  condition:
    any of them
}