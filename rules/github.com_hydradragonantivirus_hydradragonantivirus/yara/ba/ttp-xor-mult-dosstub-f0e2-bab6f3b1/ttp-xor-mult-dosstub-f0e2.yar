rule TTP_XOR_MULT_DOSStub_f0e2 {
  strings:
    $key_f0e2 = { a4 8a [2] d0 92 [2] 97 90 [2] d0 81 [2] 9e 8d [2] 92 87 [2] 85 8c [2] 9e c2 [2] a3 }

  condition:
    any of them
}