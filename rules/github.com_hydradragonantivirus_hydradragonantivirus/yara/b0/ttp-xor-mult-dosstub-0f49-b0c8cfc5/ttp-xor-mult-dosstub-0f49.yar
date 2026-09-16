rule TTP_XOR_MULT_DOSStub_0f49 {
  strings:
    $key_0f49 = { 5b 21 [2] 2f 39 [2] 68 3b [2] 2f 2a [2] 61 26 [2] 6d 2c [2] 7a 27 [2] 61 69 [2] 5c }

  condition:
    any of them
}