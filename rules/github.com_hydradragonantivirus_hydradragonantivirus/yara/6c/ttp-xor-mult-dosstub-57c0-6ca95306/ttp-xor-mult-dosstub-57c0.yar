rule TTP_XOR_MULT_DOSStub_57c0 {
  strings:
    $key_57c0 = { 03 a8 [2] 77 b0 [2] 30 b2 [2] 77 a3 [2] 39 af [2] 35 a5 [2] 22 ae [2] 39 e0 [2] 04 }

  condition:
    any of them
}