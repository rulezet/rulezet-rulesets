rule TTP_XOR_MULT_DOSStub_37f5 {
  strings:
    $key_37f5 = { 63 9d [2] 17 85 [2] 50 87 [2] 17 96 [2] 59 9a [2] 55 90 [2] 42 9b [2] 59 d5 [2] 64 }

  condition:
    any of them
}