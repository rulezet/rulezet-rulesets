rule TTP_XOR_MULT_DOSStub_0ef6 {
  strings:
    $key_0ef6 = { 5a 9e [2] 2e 86 [2] 69 84 [2] 2e 95 [2] 60 99 [2] 6c 93 [2] 7b 98 [2] 60 d6 [2] 5d }

  condition:
    any of them
}