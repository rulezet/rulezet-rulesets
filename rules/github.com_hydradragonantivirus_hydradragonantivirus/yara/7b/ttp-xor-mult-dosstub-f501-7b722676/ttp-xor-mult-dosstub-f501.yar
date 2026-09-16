rule TTP_XOR_MULT_DOSStub_f501 {
  strings:
    $key_f501 = { a1 69 [2] d5 71 [2] 92 73 [2] d5 62 [2] 9b 6e [2] 97 64 [2] 80 6f [2] 9b 21 [2] a6 }

  condition:
    any of them
}