rule TTP_XOR_MULT_DOSStub_f3e2 {
  strings:
    $key_f3e2 = { a7 8a [2] d3 92 [2] 94 90 [2] d3 81 [2] 9d 8d [2] 91 87 [2] 86 8c [2] 9d c2 [2] a0 }

  condition:
    any of them
}