rule TTP_XOR_MULT_DOSStub_3a09 {
  strings:
    $key_3a09 = { 6e 61 [2] 1a 79 [2] 5d 7b [2] 1a 6a [2] 54 66 [2] 58 6c [2] 4f 67 [2] 54 29 [2] 69 }

  condition:
    any of them
}