rule TTP_XOR_MULT_DOSStub_056e {
  strings:
    $key_056e = { 51 06 [2] 25 1e [2] 62 1c [2] 25 0d [2] 6b 01 [2] 67 0b [2] 70 00 [2] 6b 4e [2] 56 }

  condition:
    any of them
}