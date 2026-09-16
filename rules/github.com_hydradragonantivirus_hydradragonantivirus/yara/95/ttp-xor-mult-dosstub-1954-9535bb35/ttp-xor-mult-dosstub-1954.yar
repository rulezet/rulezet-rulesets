rule TTP_XOR_MULT_DOSStub_1954 {
  strings:
    $key_1954 = { 4d 3c [2] 39 24 [2] 7e 26 [2] 39 37 [2] 77 3b [2] 7b 31 [2] 6c 3a [2] 77 74 [2] 4a }

  condition:
    any of them
}