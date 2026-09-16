rule TTP_XOR_MULT_DOSStub_0b48 {
  strings:
    $key_0b48 = { 5f 20 [2] 2b 38 [2] 6c 3a [2] 2b 2b [2] 65 27 [2] 69 2d [2] 7e 26 [2] 65 68 [2] 58 }

  condition:
    any of them
}