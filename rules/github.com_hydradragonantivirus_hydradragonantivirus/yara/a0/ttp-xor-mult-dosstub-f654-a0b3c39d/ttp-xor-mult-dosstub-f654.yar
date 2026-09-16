rule TTP_XOR_MULT_DOSStub_f654 {
  strings:
    $key_f654 = { a2 3c [2] d6 24 [2] 91 26 [2] d6 37 [2] 98 3b [2] 94 31 [2] 83 3a [2] 98 74 [2] a5 }

  condition:
    any of them
}