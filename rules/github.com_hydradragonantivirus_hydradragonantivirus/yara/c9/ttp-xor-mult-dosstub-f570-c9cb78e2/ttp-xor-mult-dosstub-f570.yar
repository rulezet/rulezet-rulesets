rule TTP_XOR_MULT_DOSStub_f570 {
  strings:
    $key_f570 = { a1 18 [2] d5 00 [2] 92 02 [2] d5 13 [2] 9b 1f [2] 97 15 [2] 80 1e [2] 9b 50 [2] a6 }

  condition:
    any of them
}