rule TTP_XOR_MULT_DOSStub_f20b {
  strings:
    $key_f20b = { a6 63 [2] d2 7b [2] 95 79 [2] d2 68 [2] 9c 64 [2] 90 6e [2] 87 65 [2] 9c 2b [2] a1 }

  condition:
    any of them
}