rule TTP_XOR_MULT_DOSStub_1a01 {
  strings:
    $key_1a01 = { 4e 69 [2] 3a 71 [2] 7d 73 [2] 3a 62 [2] 74 6e [2] 78 64 [2] 6f 6f [2] 74 21 [2] 49 }

  condition:
    any of them
}