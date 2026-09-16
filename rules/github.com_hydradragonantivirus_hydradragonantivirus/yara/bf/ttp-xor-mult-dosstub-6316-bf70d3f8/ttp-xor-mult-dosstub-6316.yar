rule TTP_XOR_MULT_DOSStub_6316 {
  strings:
    $key_6316 = { 37 7e [2] 43 66 [2] 04 64 [2] 43 75 [2] 0d 79 [2] 01 73 [2] 16 78 [2] 0d 36 [2] 30 }

  condition:
    any of them
}