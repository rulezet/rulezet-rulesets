rule TTP_XOR_MULT_DOSStub_11c0 {
  strings:
    $key_11c0 = { 45 a8 [2] 31 b0 [2] 76 b2 [2] 31 a3 [2] 7f af [2] 73 a5 [2] 64 ae [2] 7f e0 [2] 42 }

  condition:
    any of them
}