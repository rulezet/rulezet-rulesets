rule TTP_XOR_MULT_DOSStub_3600 {
  strings:
    $key_3600 = { 62 68 [2] 16 70 [2] 51 72 [2] 16 63 [2] 58 6f [2] 54 65 [2] 43 6e [2] 58 20 [2] 65 }

  condition:
    any of them
}