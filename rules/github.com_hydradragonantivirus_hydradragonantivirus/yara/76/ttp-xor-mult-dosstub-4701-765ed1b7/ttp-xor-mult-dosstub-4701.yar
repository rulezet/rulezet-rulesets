rule TTP_XOR_MULT_DOSStub_4701 {
  strings:
    $key_4701 = { 13 69 [2] 67 71 [2] 20 73 [2] 67 62 [2] 29 6e [2] 25 64 [2] 32 6f [2] 29 21 [2] 14 }

  condition:
    any of them
}