rule TTP_XOR_MULT_DOSStub_5a79 {
  strings:
    $key_5a79 = { 0e 11 [2] 7a 09 [2] 3d 0b [2] 7a 1a [2] 34 16 [2] 38 1c [2] 2f 17 [2] 34 59 [2] 09 }

  condition:
    any of them
}