rule TTP_XOR_MULT_DOSStub_0b09 {
  strings:
    $key_0b09 = { 5f 61 [2] 2b 79 [2] 6c 7b [2] 2b 6a [2] 65 66 [2] 69 6c [2] 7e 67 [2] 65 29 [2] 58 }

  condition:
    any of them
}