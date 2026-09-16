rule TTP_XOR_MULT_DOSStub_2004 {
  strings:
    $key_2004 = { 74 6c [2] 00 74 [2] 47 76 [2] 00 67 [2] 4e 6b [2] 42 61 [2] 55 6a [2] 4e 24 [2] 73 }

  condition:
    any of them
}