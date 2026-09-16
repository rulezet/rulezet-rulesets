rule TTP_XOR_MULT_DOSStub_2072 {
  strings:
    $key_2072 = { 74 1a [2] 00 02 [2] 47 00 [2] 00 11 [2] 4e 1d [2] 42 17 [2] 55 1c [2] 4e 52 [2] 73 }

  condition:
    any of them
}