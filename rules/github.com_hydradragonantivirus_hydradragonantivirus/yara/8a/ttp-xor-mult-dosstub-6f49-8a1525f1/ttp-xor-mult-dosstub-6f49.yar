rule TTP_XOR_MULT_DOSStub_6f49 {
  strings:
    $key_6f49 = { 3b 21 [2] 4f 39 [2] 08 3b [2] 4f 2a [2] 01 26 [2] 0d 2c [2] 1a 27 [2] 01 69 [2] 3c }

  condition:
    any of them
}