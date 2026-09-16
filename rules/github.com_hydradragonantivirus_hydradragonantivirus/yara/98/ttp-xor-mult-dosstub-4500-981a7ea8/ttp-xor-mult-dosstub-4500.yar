rule TTP_XOR_MULT_DOSStub_4500 {
  strings:
    $key_4500 = { 11 68 [2] 65 70 [2] 22 72 [2] 65 63 [2] 2b 6f [2] 27 65 [2] 30 6e [2] 2b 20 [2] 16 }

  condition:
    any of them
}