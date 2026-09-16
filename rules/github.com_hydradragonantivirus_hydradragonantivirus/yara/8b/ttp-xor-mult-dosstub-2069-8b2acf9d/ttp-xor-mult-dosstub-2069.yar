rule TTP_XOR_MULT_DOSStub_2069 {
  strings:
    $key_2069 = { 74 01 [2] 00 19 [2] 47 1b [2] 00 0a [2] 4e 06 [2] 42 0c [2] 55 07 [2] 4e 49 [2] 73 }

  condition:
    any of them
}