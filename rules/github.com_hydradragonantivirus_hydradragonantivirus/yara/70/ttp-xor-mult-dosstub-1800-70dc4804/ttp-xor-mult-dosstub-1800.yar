rule TTP_XOR_MULT_DOSStub_1800 {
  strings:
    $key_1800 = { 4c 68 [2] 38 70 [2] 7f 72 [2] 38 63 [2] 76 6f [2] 7a 65 [2] 6d 6e [2] 76 20 [2] 4b }

  condition:
    any of them
}