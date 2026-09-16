rule TTP_XOR_MULT_DOSStub_f2e7 {
  strings:
    $key_f2e7 = { a6 8f [2] d2 97 [2] 95 95 [2] d2 84 [2] 9c 88 [2] 90 82 [2] 87 89 [2] 9c c7 [2] a1 }

  condition:
    any of them
}