rule TTP_XOR_MULT_DOSStub_0ee4 {
  strings:
    $key_0ee4 = { 5a 8c [2] 2e 94 [2] 69 96 [2] 2e 87 [2] 60 8b [2] 6c 81 [2] 7b 8a [2] 60 c4 [2] 5d }

  condition:
    any of them
}