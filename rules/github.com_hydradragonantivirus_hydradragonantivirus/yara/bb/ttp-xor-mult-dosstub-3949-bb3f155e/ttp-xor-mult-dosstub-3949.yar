rule TTP_XOR_MULT_DOSStub_3949 {
  strings:
    $key_3949 = { 6d 21 [2] 19 39 [2] 5e 3b [2] 19 2a [2] 57 26 [2] 5b 2c [2] 4c 27 [2] 57 69 [2] 6a }

  condition:
    any of them
}