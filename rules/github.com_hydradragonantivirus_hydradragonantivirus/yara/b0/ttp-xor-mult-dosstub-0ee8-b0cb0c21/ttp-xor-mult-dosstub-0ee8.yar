rule TTP_XOR_MULT_DOSStub_0ee8 {
  strings:
    $key_0ee8 = { 5a 80 [2] 2e 98 [2] 69 9a [2] 2e 8b [2] 60 87 [2] 6c 8d [2] 7b 86 [2] 60 c8 [2] 5d }

  condition:
    any of them
}