rule TTP_XOR_MULT_DOSStub_0306 {
  strings:
    $key_0306 = { 57 6e [2] 23 76 [2] 64 74 [2] 23 65 [2] 6d 69 [2] 61 63 [2] 76 68 [2] 6d 26 [2] 50 }

  condition:
    any of them
}