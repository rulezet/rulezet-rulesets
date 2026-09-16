rule TTP_XOR_MULT_DOSStub_f219 {
  strings:
    $key_f219 = { a6 71 [2] d2 69 [2] 95 6b [2] d2 7a [2] 9c 76 [2] 90 7c [2] 87 77 [2] 9c 39 [2] a1 }

  condition:
    any of them
}