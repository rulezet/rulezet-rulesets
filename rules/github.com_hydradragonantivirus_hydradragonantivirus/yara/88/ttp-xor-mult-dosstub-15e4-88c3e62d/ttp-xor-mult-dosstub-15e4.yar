rule TTP_XOR_MULT_DOSStub_15e4 {
  strings:
    $key_15e4 = { 41 8c [2] 35 94 [2] 72 96 [2] 35 87 [2] 7b 8b [2] 77 81 [2] 60 8a [2] 7b c4 [2] 46 }

  condition:
    any of them
}