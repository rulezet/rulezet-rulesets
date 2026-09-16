rule TTP_XOR_MULT_DOSStub_47e8 {
  strings:
    $key_47e8 = { 13 80 [2] 67 98 [2] 20 9a [2] 67 8b [2] 29 87 [2] 25 8d [2] 32 86 [2] 29 c8 [2] 14 }

  condition:
    any of them
}