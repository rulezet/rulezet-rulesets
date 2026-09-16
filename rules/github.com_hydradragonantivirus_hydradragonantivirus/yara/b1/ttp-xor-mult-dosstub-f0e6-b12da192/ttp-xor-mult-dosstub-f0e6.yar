rule TTP_XOR_MULT_DOSStub_f0e6 {
  strings:
    $key_f0e6 = { a4 8e [2] d0 96 [2] 97 94 [2] d0 85 [2] 9e 89 [2] 92 83 [2] 85 88 [2] 9e c6 [2] a3 }

  condition:
    any of them
}