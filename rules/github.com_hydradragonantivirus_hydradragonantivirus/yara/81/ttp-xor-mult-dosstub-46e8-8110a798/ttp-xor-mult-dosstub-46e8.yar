rule TTP_XOR_MULT_DOSStub_46e8 {
  strings:
    $key_46e8 = { 12 80 [2] 66 98 [2] 21 9a [2] 66 8b [2] 28 87 [2] 24 8d [2] 33 86 [2] 28 c8 [2] 15 }

  condition:
    any of them
}