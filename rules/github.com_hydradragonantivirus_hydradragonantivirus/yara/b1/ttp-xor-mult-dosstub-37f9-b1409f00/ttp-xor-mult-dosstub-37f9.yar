rule TTP_XOR_MULT_DOSStub_37f9 {
  strings:
    $key_37f9 = { 63 91 [2] 17 89 [2] 50 8b [2] 17 9a [2] 59 96 [2] 55 9c [2] 42 97 [2] 59 d9 [2] 64 }

  condition:
    any of them
}