rule TTP_XOR_MULT_DOSStub_2019 {
  strings:
    $key_2019 = { 74 71 [2] 00 69 [2] 47 6b [2] 00 7a [2] 4e 76 [2] 42 7c [2] 55 77 [2] 4e 39 [2] 73 }

  condition:
    any of them
}