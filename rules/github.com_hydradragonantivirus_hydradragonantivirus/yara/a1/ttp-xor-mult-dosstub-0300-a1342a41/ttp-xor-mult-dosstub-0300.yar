rule TTP_XOR_MULT_DOSStub_0300 {
  strings:
    $key_0300 = { 57 68 [2] 23 70 [2] 64 72 [2] 23 63 [2] 6d 6f [2] 61 65 [2] 76 6e [2] 6d 20 [2] 50 }

  condition:
    any of them
}