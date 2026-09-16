rule TTP_XOR_MULT_DOSStub_7601 {
  strings:
    $key_7601 = { 22 69 [2] 56 71 [2] 11 73 [2] 56 62 [2] 18 6e [2] 14 64 [2] 03 6f [2] 18 21 [2] 25 }

  condition:
    any of them
}