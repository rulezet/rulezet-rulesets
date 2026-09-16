rule TTP_XOR_MULT_DOSStub_37f8 {
  strings:
    $key_37f8 = { 63 90 [2] 17 88 [2] 50 8a [2] 17 9b [2] 59 97 [2] 55 9d [2] 42 96 [2] 59 d8 [2] 64 }

  condition:
    any of them
}