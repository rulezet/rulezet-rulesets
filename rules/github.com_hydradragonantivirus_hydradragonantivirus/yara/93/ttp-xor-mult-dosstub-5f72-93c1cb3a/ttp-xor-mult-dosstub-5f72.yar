rule TTP_XOR_MULT_DOSStub_5f72 {
  strings:
    $key_5f72 = { 0b 1a [2] 7f 02 [2] 38 00 [2] 7f 11 [2] 31 1d [2] 3d 17 [2] 2a 1c [2] 31 52 [2] 0c }

  condition:
    any of them
}