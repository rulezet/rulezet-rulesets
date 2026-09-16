rule TTP_XOR_MULT_DOSStub_3f49 {
  strings:
    $key_3f49 = { 6b 21 [2] 1f 39 [2] 58 3b [2] 1f 2a [2] 51 26 [2] 5d 2c [2] 4a 27 [2] 51 69 [2] 6c }

  condition:
    any of them
}