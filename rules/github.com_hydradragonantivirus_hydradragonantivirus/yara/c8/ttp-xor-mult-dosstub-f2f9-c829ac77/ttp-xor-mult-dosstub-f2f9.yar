rule TTP_XOR_MULT_DOSStub_f2f9 {
  strings:
    $key_f2f9 = { a6 91 [2] d2 89 [2] 95 8b [2] d2 9a [2] 9c 96 [2] 90 9c [2] 87 97 [2] 9c d9 [2] a1 }

  condition:
    any of them
}