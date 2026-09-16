rule TTP_XOR_MULT_DOSStub_0949 {
  strings:
    $key_0949 = { 5d 21 [2] 29 39 [2] 6e 3b [2] 29 2a [2] 67 26 [2] 6b 2c [2] 7c 27 [2] 67 69 [2] 5a }

  condition:
    any of them
}