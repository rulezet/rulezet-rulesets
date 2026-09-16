rule TTP_XOR_MULT_DOSStub_2ae4 {
  strings:
    $key_2ae4 = { 7e 8c [2] 0a 94 [2] 4d 96 [2] 0a 87 [2] 44 8b [2] 48 81 [2] 5f 8a [2] 44 c4 [2] 79 }

  condition:
    any of them
}