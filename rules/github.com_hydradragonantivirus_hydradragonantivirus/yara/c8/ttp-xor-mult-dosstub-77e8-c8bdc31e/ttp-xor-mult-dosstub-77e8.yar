rule TTP_XOR_MULT_DOSStub_77e8 {
  strings:
    $key_77e8 = { 23 80 [2] 57 98 [2] 10 9a [2] 57 8b [2] 19 87 [2] 15 8d [2] 02 86 [2] 19 c8 [2] 24 }

  condition:
    any of them
}