rule TTP_XOR_MULT_DOSStub_1949 {
  strings:
    $key_1949 = { 4d 21 [2] 39 39 [2] 7e 3b [2] 39 2a [2] 77 26 [2] 7b 2c [2] 6c 27 [2] 77 69 [2] 4a }

  condition:
    any of them
}