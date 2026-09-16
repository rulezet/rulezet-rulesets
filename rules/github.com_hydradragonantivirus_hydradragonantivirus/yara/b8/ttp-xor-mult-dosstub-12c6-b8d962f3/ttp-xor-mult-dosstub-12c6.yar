rule TTP_XOR_MULT_DOSStub_12c6 {
  strings:
    $key_12c6 = { 46 ae [2] 32 b6 [2] 75 b4 [2] 32 a5 [2] 7c a9 [2] 70 a3 [2] 67 a8 [2] 7c e6 [2] 41 }

  condition:
    any of them
}