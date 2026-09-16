rule TTP_XOR_MULT_DOSStub_0b34 {
  strings:
    $key_0b34 = { 5f 5c [2] 2b 44 [2] 6c 46 [2] 2b 57 [2] 65 5b [2] 69 51 [2] 7e 5a [2] 65 14 [2] 58 }

  condition:
    any of them
}