rule TTP_XOR_MULT_DOSStub_7a00 {
  strings:
    $key_7a00 = { 2e 68 [2] 5a 70 [2] 1d 72 [2] 5a 63 [2] 14 6f [2] 18 65 [2] 0f 6e [2] 14 20 [2] 29 }

  condition:
    any of them
}