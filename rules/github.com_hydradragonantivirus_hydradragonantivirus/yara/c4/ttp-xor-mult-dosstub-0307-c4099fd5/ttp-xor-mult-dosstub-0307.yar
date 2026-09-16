rule TTP_XOR_MULT_DOSStub_0307 {
  strings:
    $key_0307 = { 57 6f [2] 23 77 [2] 64 75 [2] 23 64 [2] 6d 68 [2] 61 62 [2] 76 69 [2] 6d 27 [2] 50 }

  condition:
    any of them
}