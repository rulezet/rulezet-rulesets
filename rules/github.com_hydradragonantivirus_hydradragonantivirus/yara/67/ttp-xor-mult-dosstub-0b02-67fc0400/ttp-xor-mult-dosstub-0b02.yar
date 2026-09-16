rule TTP_XOR_MULT_DOSStub_0b02 {
  strings:
    $key_0b02 = { 5f 6a [2] 2b 72 [2] 6c 70 [2] 2b 61 [2] 65 6d [2] 69 67 [2] 7e 6c [2] 65 22 [2] 58 }

  condition:
    any of them
}