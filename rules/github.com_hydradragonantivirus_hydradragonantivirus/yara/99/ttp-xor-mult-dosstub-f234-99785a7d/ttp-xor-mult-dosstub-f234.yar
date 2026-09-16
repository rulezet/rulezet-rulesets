rule TTP_XOR_MULT_DOSStub_f234 {
  strings:
    $key_f234 = { a6 5c [2] d2 44 [2] 95 46 [2] d2 57 [2] 9c 5b [2] 90 51 [2] 87 5a [2] 9c 14 [2] a1 }

  condition:
    any of them
}