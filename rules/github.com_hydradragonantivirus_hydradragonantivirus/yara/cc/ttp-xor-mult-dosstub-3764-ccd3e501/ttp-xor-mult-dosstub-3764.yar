rule TTP_XOR_MULT_DOSStub_3764 {
  strings:
    $key_3764 = { 63 0c [2] 17 14 [2] 50 16 [2] 17 07 [2] 59 0b [2] 55 01 [2] 42 0a [2] 59 44 [2] 64 }

  condition:
    any of them
}