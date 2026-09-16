rule TTP_XOR_MULT_DOSStub_09e4 {
  strings:
    $key_09e4 = { 5d 8c [2] 29 94 [2] 6e 96 [2] 29 87 [2] 67 8b [2] 6b 81 [2] 7c 8a [2] 67 c4 [2] 5a }

  condition:
    any of them
}