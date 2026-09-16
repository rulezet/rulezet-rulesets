rule TTP_XOR_MULT_DOSStub_2b34 {
  strings:
    $key_2b34 = { 7f 5c [2] 0b 44 [2] 4c 46 [2] 0b 57 [2] 45 5b [2] 49 51 [2] 5e 5a [2] 45 14 [2] 78 }

  condition:
    any of them
}