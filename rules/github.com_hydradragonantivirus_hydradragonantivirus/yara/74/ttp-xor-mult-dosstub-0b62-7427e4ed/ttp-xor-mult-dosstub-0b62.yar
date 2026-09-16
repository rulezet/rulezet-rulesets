rule TTP_XOR_MULT_DOSStub_0b62 {
  strings:
    $key_0b62 = { 5f 0a [2] 2b 12 [2] 6c 10 [2] 2b 01 [2] 65 0d [2] 69 07 [2] 7e 0c [2] 65 42 [2] 58 }

  condition:
    any of them
}