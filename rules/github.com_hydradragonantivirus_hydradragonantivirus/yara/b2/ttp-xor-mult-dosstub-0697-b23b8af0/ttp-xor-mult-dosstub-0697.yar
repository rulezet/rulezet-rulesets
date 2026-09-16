rule TTP_XOR_MULT_DOSStub_0697 {
  strings:
    $key_0697 = { 52 ff [2] 26 e7 [2] 61 e5 [2] 26 f4 [2] 68 f8 [2] 64 f2 [2] 73 f9 [2] 68 b7 [2] 55 }

  condition:
    any of them
}