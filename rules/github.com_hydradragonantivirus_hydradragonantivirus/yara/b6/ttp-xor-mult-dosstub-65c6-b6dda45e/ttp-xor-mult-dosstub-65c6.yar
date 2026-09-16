rule TTP_XOR_MULT_DOSStub_65c6 {
  strings:
    $key_65c6 = { 31 ae [2] 45 b6 [2] 02 b4 [2] 45 a5 [2] 0b a9 [2] 07 a3 [2] 10 a8 [2] 0b e6 [2] 36 }

  condition:
    any of them
}