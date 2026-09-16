rule TTP_XOR_MULT_DOSStub_0707 {
  strings:
    $key_0707 = { 53 6f [2] 27 77 [2] 60 75 [2] 27 64 [2] 69 68 [2] 65 62 [2] 72 69 [2] 69 27 [2] 54 }

  condition:
    any of them
}