rule TTP_XOR_MULT_DOSStub_4601 {
  strings:
    $key_4601 = { 12 69 [2] 66 71 [2] 21 73 [2] 66 62 [2] 28 6e [2] 24 64 [2] 33 6f [2] 28 21 [2] 15 }

  condition:
    any of them
}