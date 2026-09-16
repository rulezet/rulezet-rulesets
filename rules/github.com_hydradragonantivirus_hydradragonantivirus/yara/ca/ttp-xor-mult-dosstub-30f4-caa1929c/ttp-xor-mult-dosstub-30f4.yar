rule TTP_XOR_MULT_DOSStub_30f4 {
  strings:
    $key_30f4 = { 64 9c [2] 10 84 [2] 57 86 [2] 10 97 [2] 5e 9b [2] 52 91 [2] 45 9a [2] 5e d4 [2] 63 }

  condition:
    any of them
}