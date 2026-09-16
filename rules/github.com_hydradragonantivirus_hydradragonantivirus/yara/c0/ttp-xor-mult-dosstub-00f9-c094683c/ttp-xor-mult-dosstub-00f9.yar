rule TTP_XOR_MULT_DOSStub_00f9 {
  strings:
    $key_00f9 = { 54 91 [2] 20 89 [2] 67 8b [2] 20 9a [2] 6e 96 [2] 62 9c [2] 75 97 [2] 6e d9 [2] 53 }

  condition:
    any of them
}