rule TTP_XOR_MULT_DOSStub_2059 {
  strings:
    $key_2059 = { 74 31 [2] 00 29 [2] 47 2b [2] 00 3a [2] 4e 36 [2] 42 3c [2] 55 37 [2] 4e 79 [2] 73 }

  condition:
    any of them
}