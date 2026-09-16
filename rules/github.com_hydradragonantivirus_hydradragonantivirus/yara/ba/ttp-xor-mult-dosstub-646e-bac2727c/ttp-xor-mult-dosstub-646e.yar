rule TTP_XOR_MULT_DOSStub_646e {
  strings:
    $key_646e = { 30 06 [2] 44 1e [2] 03 1c [2] 44 0d [2] 0a 01 [2] 06 0b [2] 11 00 [2] 0a 4e [2] 37 }

  condition:
    any of them
}