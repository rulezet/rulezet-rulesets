rule TTP_XOR_MULT_DOSStub_30f9 {
  strings:
    $key_30f9 = { 64 91 [2] 10 89 [2] 57 8b [2] 10 9a [2] 5e 96 [2] 52 9c [2] 45 97 [2] 5e d9 [2] 63 }

  condition:
    any of them
}