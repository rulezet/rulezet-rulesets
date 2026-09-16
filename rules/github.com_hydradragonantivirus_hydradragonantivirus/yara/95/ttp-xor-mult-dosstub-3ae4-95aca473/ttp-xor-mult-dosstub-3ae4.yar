rule TTP_XOR_MULT_DOSStub_3ae4 {
  strings:
    $key_3ae4 = { 6e 8c [2] 1a 94 [2] 5d 96 [2] 1a 87 [2] 54 8b [2] 58 81 [2] 4f 8a [2] 54 c4 [2] 69 }

  condition:
    any of them
}