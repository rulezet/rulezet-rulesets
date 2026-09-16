rule TTP_XOR_MULT_DOSStub_f001 {
  strings:
    $key_f001 = { a4 69 [2] d0 71 [2] 97 73 [2] d0 62 [2] 9e 6e [2] 92 64 [2] 85 6f [2] 9e 21 [2] a3 }

  condition:
    any of them
}