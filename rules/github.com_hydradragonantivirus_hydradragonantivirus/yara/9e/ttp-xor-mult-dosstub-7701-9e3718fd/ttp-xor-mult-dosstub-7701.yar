rule TTP_XOR_MULT_DOSStub_7701 {
  strings:
    $key_7701 = { 23 69 [2] 57 71 [2] 10 73 [2] 57 62 [2] 19 6e [2] 15 64 [2] 02 6f [2] 19 21 [2] 24 }

  condition:
    any of them
}