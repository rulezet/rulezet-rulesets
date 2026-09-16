rule TTP_XOR_MULT_DOSStub_0954 {
  strings:
    $key_0954 = { 5d 3c [2] 29 24 [2] 6e 26 [2] 29 37 [2] 67 3b [2] 6b 31 [2] 7c 3a [2] 67 74 [2] 5a }

  condition:
    any of them
}