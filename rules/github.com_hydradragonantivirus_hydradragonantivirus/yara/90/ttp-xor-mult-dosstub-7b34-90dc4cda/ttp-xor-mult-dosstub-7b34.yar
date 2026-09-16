rule TTP_XOR_MULT_DOSStub_7b34 {
  strings:
    $key_7b34 = { 2f 5c [2] 5b 44 [2] 1c 46 [2] 5b 57 [2] 15 5b [2] 19 51 [2] 0e 5a [2] 15 14 [2] 28 }

  condition:
    any of them
}