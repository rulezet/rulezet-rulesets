rule TTP_XOR_MULT_DOSStub_3b34 {
  strings:
    $key_3b34 = { 6f 5c [2] 1b 44 [2] 5c 46 [2] 1b 57 [2] 55 5b [2] 59 51 [2] 4e 5a [2] 55 14 [2] 68 }

  condition:
    any of them
}