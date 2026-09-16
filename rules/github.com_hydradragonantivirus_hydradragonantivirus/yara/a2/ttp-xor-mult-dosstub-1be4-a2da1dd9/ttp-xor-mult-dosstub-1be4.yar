rule TTP_XOR_MULT_DOSStub_1be4 {
  strings:
    $key_1be4 = { 4f 8c [2] 3b 94 [2] 7c 96 [2] 3b 87 [2] 75 8b [2] 79 81 [2] 6e 8a [2] 75 c4 [2] 48 }

  condition:
    any of them
}