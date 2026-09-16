rule TTP_XOR_MULT_DOSStub_f208 {
  strings:
    $key_f208 = { a6 60 [2] d2 78 [2] 95 7a [2] d2 6b [2] 9c 67 [2] 90 6d [2] 87 66 [2] 9c 28 [2] a1 }

  condition:
    any of them
}