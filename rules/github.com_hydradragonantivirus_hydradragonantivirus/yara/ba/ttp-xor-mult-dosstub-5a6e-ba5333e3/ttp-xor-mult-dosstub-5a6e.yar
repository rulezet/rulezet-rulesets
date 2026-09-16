rule TTP_XOR_MULT_DOSStub_5a6e {
  strings:
    $key_5a6e = { 0e 06 [2] 7a 1e [2] 3d 1c [2] 7a 0d [2] 34 01 [2] 38 0b [2] 2f 00 [2] 34 4e [2] 09 }

  condition:
    any of them
}