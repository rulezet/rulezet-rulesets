rule TTP_XOR_MULT_DOSStub_f006 {
  strings:
    $key_f006 = { a4 6e [2] d0 76 [2] 97 74 [2] d0 65 [2] 9e 69 [2] 92 63 [2] 85 68 [2] 9e 26 [2] a3 }

  condition:
    any of them
}