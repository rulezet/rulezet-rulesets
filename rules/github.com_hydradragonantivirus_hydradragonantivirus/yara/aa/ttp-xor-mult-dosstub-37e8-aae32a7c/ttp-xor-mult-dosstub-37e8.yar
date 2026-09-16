rule TTP_XOR_MULT_DOSStub_37e8 {
  strings:
    $key_37e8 = { 63 80 [2] 17 98 [2] 50 9a [2] 17 8b [2] 59 87 [2] 55 8d [2] 42 86 [2] 59 c8 [2] 64 }

  condition:
    any of them
}