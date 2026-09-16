rule TTP_XOR_MULT_DOSStub_f254 {
  strings:
    $key_f254 = { a6 3c [2] d2 24 [2] 95 26 [2] d2 37 [2] 9c 3b [2] 90 31 [2] 87 3a [2] 9c 74 [2] a1 }

  condition:
    any of them
}