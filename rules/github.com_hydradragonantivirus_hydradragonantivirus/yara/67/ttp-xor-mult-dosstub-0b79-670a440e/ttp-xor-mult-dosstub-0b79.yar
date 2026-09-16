rule TTP_XOR_MULT_DOSStub_0b79 {
  strings:
    $key_0b79 = { 5f 11 [2] 2b 09 [2] 6c 0b [2] 2b 1a [2] 65 16 [2] 69 1c [2] 7e 17 [2] 65 59 [2] 58 }

  condition:
    any of them
}