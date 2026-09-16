rule TTP_XOR_MULT_DOSStub_5be9 {
  strings:
    $key_5be9 = { 0f 81 [2] 7b 99 [2] 3c 9b [2] 7b 8a [2] 35 86 [2] 39 8c [2] 2e 87 [2] 35 c9 [2] 08 }

  condition:
    any of them
}