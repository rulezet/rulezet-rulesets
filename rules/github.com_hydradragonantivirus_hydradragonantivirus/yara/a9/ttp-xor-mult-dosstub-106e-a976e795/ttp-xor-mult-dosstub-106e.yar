rule TTP_XOR_MULT_DOSStub_106e {
  strings:
    $key_106e = { 44 06 [2] 30 1e [2] 77 1c [2] 30 0d [2] 7e 01 [2] 72 0b [2] 65 00 [2] 7e 4e [2] 43 }

  condition:
    any of them
}