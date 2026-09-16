rule TTP_XOR_MULT_DOSStub_2606 {
  strings:
    $key_2606 = { 72 6e [2] 06 76 [2] 41 74 [2] 06 65 [2] 48 69 [2] 44 63 [2] 53 68 [2] 48 26 [2] 75 }

  condition:
    any of them
}