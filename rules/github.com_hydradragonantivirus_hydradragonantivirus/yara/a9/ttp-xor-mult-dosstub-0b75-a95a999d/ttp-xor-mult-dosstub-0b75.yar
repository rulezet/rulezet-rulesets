rule TTP_XOR_MULT_DOSStub_0b75 {
  strings:
    $key_0b75 = { 5f 1d [2] 2b 05 [2] 6c 07 [2] 2b 16 [2] 65 1a [2] 69 10 [2] 7e 1b [2] 65 55 [2] 58 }

  condition:
    any of them
}