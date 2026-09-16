rule TTP_XOR_MULT_DOSStub_75f9 {
  strings:
    $key_75f9 = { 21 91 [2] 55 89 [2] 12 8b [2] 55 9a [2] 1b 96 [2] 17 9c [2] 00 97 [2] 1b d9 [2] 26 }

  condition:
    any of them
}