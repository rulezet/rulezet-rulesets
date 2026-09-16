rule TTP_XOR_MULT_DOSStub_7216 {
  strings:
    $key_7216 = { 26 7e [2] 52 66 [2] 15 64 [2] 52 75 [2] 1c 79 [2] 10 73 [2] 07 78 [2] 1c 36 [2] 21 }

  condition:
    any of them
}