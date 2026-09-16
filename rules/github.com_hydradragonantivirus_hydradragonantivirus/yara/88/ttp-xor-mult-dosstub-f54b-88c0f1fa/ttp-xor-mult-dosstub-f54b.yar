rule TTP_XOR_MULT_DOSStub_f54b {
  strings:
    $key_f54b = { a1 23 [2] d5 3b [2] 92 39 [2] d5 28 [2] 9b 24 [2] 97 2e [2] 80 25 [2] 9b 6b [2] a6 }

  condition:
    any of them
}