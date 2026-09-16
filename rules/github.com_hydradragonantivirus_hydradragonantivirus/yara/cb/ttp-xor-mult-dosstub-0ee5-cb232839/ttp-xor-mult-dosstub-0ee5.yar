rule TTP_XOR_MULT_DOSStub_0ee5 {
  strings:
    $key_0ee5 = { 5a 8d [2] 2e 95 [2] 69 97 [2] 2e 86 [2] 60 8a [2] 6c 80 [2] 7b 8b [2] 60 c5 [2] 5d }

  condition:
    any of them
}