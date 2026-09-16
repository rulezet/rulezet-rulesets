rule TTP_XOR_MULT_DOSStub_f576 {
  strings:
    $key_f576 = { a1 1e [2] d5 06 [2] 92 04 [2] d5 15 [2] 9b 19 [2] 97 13 [2] 80 18 [2] 9b 56 [2] a6 }

  condition:
    any of them
}