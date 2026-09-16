rule TTP_XOR_MULT_DOSStub_0ee6 {
  strings:
    $key_0ee6 = { 5a 8e [2] 2e 96 [2] 69 94 [2] 2e 85 [2] 60 89 [2] 6c 83 [2] 7b 88 [2] 60 c6 [2] 5d }

  condition:
    any of them
}