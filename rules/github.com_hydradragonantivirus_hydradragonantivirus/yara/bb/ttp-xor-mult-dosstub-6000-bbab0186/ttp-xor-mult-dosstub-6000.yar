rule TTP_XOR_MULT_DOSStub_6000 {
  strings:
    $key_6000 = { 34 68 [2] 40 70 [2] 07 72 [2] 40 63 [2] 0e 6f [2] 02 65 [2] 15 6e [2] 0e 20 [2] 33 }

  condition:
    any of them
}