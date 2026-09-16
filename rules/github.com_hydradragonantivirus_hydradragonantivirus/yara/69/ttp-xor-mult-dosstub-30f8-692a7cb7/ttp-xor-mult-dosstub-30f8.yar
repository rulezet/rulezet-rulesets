rule TTP_XOR_MULT_DOSStub_30f8 {
  strings:
    $key_30f8 = { 64 90 [2] 10 88 [2] 57 8a [2] 10 9b [2] 5e 97 [2] 52 9d [2] 45 96 [2] 5e d8 [2] 63 }

  condition:
    any of them
}