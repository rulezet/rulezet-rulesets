rule TTP_XOR_MULT_DOSStub_0006 {
  strings:
    $key_0006 = { 54 6e [2] 20 76 [2] 67 74 [2] 20 65 [2] 6e 69 [2] 62 63 [2] 75 68 [2] 6e 26 [2] 53 }

  condition:
    any of them
}