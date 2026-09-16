rule TTP_XOR_MULT_DOSStub_27e4 {
  strings:
    $key_27e4 = { 73 8c [2] 07 94 [2] 40 96 [2] 07 87 [2] 49 8b [2] 45 81 [2] 52 8a [2] 49 c4 [2] 74 }

  condition:
    any of them
}