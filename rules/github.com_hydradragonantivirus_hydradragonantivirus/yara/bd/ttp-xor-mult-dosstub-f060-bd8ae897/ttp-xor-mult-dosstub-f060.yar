rule TTP_XOR_MULT_DOSStub_f060 {
  strings:
    $key_f060 = { a4 08 [2] d0 10 [2] 97 12 [2] d0 03 [2] 9e 0f [2] 92 05 [2] 85 0e [2] 9e 40 [2] a3 }

  condition:
    any of them
}