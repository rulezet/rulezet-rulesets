rule TTP_XOR_MULT_DOSStub_f2e8 {
  strings:
    $key_f2e8 = { a6 80 [2] d2 98 [2] 95 9a [2] d2 8b [2] 9c 87 [2] 90 8d [2] 87 86 [2] 9c c8 [2] a1 }

  condition:
    any of them
}