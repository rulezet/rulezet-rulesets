rule TTP_XOR_MULT_DOSStub_2009 {
  strings:
    $key_2009 = { 74 61 [2] 00 79 [2] 47 7b [2] 00 6a [2] 4e 66 [2] 42 6c [2] 55 67 [2] 4e 29 [2] 73 }

  condition:
    any of them
}