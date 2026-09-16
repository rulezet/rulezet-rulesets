rule TTP_XOR_MULT_DOSStub_6472 {
  strings:
    $key_6472 = { 30 1a [2] 44 02 [2] 03 00 [2] 44 11 [2] 0a 1d [2] 06 17 [2] 11 1c [2] 0a 52 [2] 37 }

  condition:
    any of them
}