rule TTP_XOR_MULT_DOSStub_7be9 {
  strings:
    $key_7be9 = { 2f 81 [2] 5b 99 [2] 1c 9b [2] 5b 8a [2] 15 86 [2] 19 8c [2] 0e 87 [2] 15 c9 [2] 28 }

  condition:
    any of them
}