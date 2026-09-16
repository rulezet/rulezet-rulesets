rule TTP_XOR_MULT_DOSStub_f24b {
  strings:
    $key_f24b = { a6 23 [2] d2 3b [2] 95 39 [2] d2 28 [2] 9c 24 [2] 90 2e [2] 87 25 [2] 9c 6b [2] a1 }

  condition:
    any of them
}