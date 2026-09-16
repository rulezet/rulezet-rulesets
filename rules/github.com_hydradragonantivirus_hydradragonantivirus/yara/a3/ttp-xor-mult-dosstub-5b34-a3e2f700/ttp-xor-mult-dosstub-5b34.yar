rule TTP_XOR_MULT_DOSStub_5b34 {
  strings:
    $key_5b34 = { 0f 5c [2] 7b 44 [2] 3c 46 [2] 7b 57 [2] 35 5b [2] 39 51 [2] 2e 5a [2] 35 14 [2] 08 }

  condition:
    any of them
}