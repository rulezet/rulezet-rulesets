rule TTP_XOR_MULT_DOSStub_5be4 {
  strings:
    $key_5be4 = { 0f 8c [2] 7b 94 [2] 3c 96 [2] 7b 87 [2] 35 8b [2] 39 81 [2] 2e 8a [2] 35 c4 [2] 08 }

  condition:
    any of them
}