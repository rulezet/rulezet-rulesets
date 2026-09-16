rule TTP_XOR_MULT_DOSStub_32f9 {
  strings:
    $key_32f9 = { 66 91 [2] 12 89 [2] 55 8b [2] 12 9a [2] 5c 96 [2] 50 9c [2] 47 97 [2] 5c d9 [2] 61 }

  condition:
    any of them
}