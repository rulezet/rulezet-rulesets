rule TTP_XOR_MULT_DOSStub_20f5 {
  strings:
    $key_20f5 = { 74 9d [2] 00 85 [2] 47 87 [2] 00 96 [2] 4e 9a [2] 42 90 [2] 55 9b [2] 4e d5 [2] 73 }

  condition:
    any of them
}