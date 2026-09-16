rule TTP_XOR_MULT_DOSStub_0ee7 {
  strings:
    $key_0ee7 = { 5a 8f [2] 2e 97 [2] 69 95 [2] 2e 84 [2] 60 88 [2] 6c 82 [2] 7b 89 [2] 60 c7 [2] 5d }

  condition:
    any of them
}