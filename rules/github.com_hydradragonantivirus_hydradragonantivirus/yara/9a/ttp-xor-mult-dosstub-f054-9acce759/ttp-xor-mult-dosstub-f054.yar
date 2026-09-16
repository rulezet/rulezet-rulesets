rule TTP_XOR_MULT_DOSStub_f054 {
  strings:
    $key_f054 = { a4 3c [2] d0 24 [2] 97 26 [2] d0 37 [2] 9e 3b [2] 92 31 [2] 85 3a [2] 9e 74 [2] a3 }

  condition:
    any of them
}