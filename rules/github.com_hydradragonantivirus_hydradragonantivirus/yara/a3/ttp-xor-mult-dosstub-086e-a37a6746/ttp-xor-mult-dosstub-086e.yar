rule TTP_XOR_MULT_DOSStub_086e {
  strings:
    $key_086e = { 5c 06 [2] 28 1e [2] 6f 1c [2] 28 0d [2] 66 01 [2] 6a 0b [2] 7d 00 [2] 66 4e [2] 5b }

  condition:
    any of them
}