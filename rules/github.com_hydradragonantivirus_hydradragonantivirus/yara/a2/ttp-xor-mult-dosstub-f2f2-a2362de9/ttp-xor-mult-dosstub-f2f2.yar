rule TTP_XOR_MULT_DOSStub_f2f2 {
  strings:
    $key_f2f2 = { a6 9a [2] d2 82 [2] 95 80 [2] d2 91 [2] 9c 9d [2] 90 97 [2] 87 9c [2] 9c d2 [2] a1 }

  condition:
    any of them
}