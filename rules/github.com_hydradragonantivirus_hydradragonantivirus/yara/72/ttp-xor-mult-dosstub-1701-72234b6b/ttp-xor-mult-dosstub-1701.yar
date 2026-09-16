rule TTP_XOR_MULT_DOSStub_1701 {
  strings:
    $key_1701 = { 43 69 [2] 37 71 [2] 70 73 [2] 37 62 [2] 79 6e [2] 75 64 [2] 62 6f [2] 79 21 [2] 44 }

  condition:
    any of them
}