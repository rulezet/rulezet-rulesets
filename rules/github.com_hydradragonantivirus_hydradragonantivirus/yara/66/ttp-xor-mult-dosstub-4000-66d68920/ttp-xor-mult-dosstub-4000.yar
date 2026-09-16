rule TTP_XOR_MULT_DOSStub_4000 {
  strings:
    $key_4000 = { 14 68 [2] 60 70 [2] 27 72 [2] 60 63 [2] 2e 6f [2] 22 65 [2] 35 6e [2] 2e 20 [2] 13 }

  condition:
    any of them
}