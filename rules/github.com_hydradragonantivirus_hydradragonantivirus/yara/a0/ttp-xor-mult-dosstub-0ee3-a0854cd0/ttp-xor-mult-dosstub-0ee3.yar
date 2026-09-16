rule TTP_XOR_MULT_DOSStub_0ee3 {
  strings:
    $key_0ee3 = { 5a 8b [2] 2e 93 [2] 69 91 [2] 2e 80 [2] 60 8c [2] 6c 86 [2] 7b 8d [2] 60 c3 [2] 5d }

  condition:
    any of them
}