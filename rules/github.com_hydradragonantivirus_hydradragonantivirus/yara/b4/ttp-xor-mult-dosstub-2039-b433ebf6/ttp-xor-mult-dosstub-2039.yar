rule TTP_XOR_MULT_DOSStub_2039 {
  strings:
    $key_2039 = { 74 51 [2] 00 49 [2] 47 4b [2] 00 5a [2] 4e 56 [2] 42 5c [2] 55 57 [2] 4e 19 [2] 73 }

  condition:
    any of them
}