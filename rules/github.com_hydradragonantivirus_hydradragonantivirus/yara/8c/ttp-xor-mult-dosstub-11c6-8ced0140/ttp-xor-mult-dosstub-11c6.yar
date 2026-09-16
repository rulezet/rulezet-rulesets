rule TTP_XOR_MULT_DOSStub_11c6 {
  strings:
    $key_11c6 = { 45 ae [2] 31 b6 [2] 76 b4 [2] 31 a5 [2] 7f a9 [2] 73 a3 [2] 64 a8 [2] 7f e6 [2] 42 }

  condition:
    any of them
}