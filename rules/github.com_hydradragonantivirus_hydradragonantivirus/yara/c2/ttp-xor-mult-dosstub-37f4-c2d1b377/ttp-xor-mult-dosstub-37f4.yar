rule TTP_XOR_MULT_DOSStub_37f4 {
  strings:
    $key_37f4 = { 63 9c [2] 17 84 [2] 50 86 [2] 17 97 [2] 59 9b [2] 55 91 [2] 42 9a [2] 59 d4 [2] 64 }

  condition:
    any of them
}