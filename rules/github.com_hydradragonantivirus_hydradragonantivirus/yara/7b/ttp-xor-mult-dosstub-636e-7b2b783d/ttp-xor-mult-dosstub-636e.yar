rule TTP_XOR_MULT_DOSStub_636e {
  strings:
    $key_636e = { 37 06 [2] 43 1e [2] 04 1c [2] 43 0d [2] 0d 01 [2] 01 0b [2] 16 00 [2] 0d 4e [2] 30 }

  condition:
    any of them
}