rule TTP_XOR_MULT_DOSStub_f214 {
  strings:
    $key_f214 = { a6 7c [2] d2 64 [2] 95 66 [2] d2 77 [2] 9c 7b [2] 90 71 [2] 87 7a [2] 9c 34 [2] a1 }

  condition:
    any of them
}