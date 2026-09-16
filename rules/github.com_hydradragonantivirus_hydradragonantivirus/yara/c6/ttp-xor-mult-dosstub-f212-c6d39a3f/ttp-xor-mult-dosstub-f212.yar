rule TTP_XOR_MULT_DOSStub_f212 {
  strings:
    $key_f212 = { a6 7a [2] d2 62 [2] 95 60 [2] d2 71 [2] 9c 7d [2] 90 77 [2] 87 7c [2] 9c 32 [2] a1 }

  condition:
    any of them
}