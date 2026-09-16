rule TTP_XOR_MULT_DOSStub_346e {
  strings:
    $key_346e = { 60 06 [2] 14 1e [2] 53 1c [2] 14 0d [2] 5a 01 [2] 56 0b [2] 41 00 [2] 5a 4e [2] 67 }

  condition:
    any of them
}