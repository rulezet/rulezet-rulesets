rule TTP_XOR_MULT_DOSStub_15e9 {
  strings:
    $key_15e9 = { 41 81 [2] 35 99 [2] 72 9b [2] 35 8a [2] 7b 86 [2] 77 8c [2] 60 87 [2] 7b c9 [2] 46 }

  condition:
    any of them
}