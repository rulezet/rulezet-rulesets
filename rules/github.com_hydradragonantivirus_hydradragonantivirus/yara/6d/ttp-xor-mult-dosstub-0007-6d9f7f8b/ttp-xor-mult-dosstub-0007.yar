rule TTP_XOR_MULT_DOSStub_0007 {
  strings:
    $key_0007 = { 54 6f [2] 20 77 [2] 67 75 [2] 20 64 [2] 6e 68 [2] 62 62 [2] 75 69 [2] 6e 27 [2] 53 }

  condition:
    any of them
}