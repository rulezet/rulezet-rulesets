rule TTP_XOR_MULT_DOSStub_0ee9 {
  strings:
    $key_0ee9 = { 5a 81 [2] 2e 99 [2] 69 9b [2] 2e 8a [2] 60 86 [2] 6c 8c [2] 7b 87 [2] 60 c9 [2] 5d }

  condition:
    any of them
}