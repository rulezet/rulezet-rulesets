rule TTP_XOR_MULT_DOSStub_f217 {
  strings:
    $key_f217 = { a6 7f [2] d2 67 [2] 95 65 [2] d2 74 [2] 9c 78 [2] 90 72 [2] 87 79 [2] 9c 37 [2] a1 }

  condition:
    any of them
}