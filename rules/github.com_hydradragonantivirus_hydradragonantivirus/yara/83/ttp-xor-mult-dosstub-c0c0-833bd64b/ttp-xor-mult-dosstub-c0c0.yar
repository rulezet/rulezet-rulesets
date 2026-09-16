rule TTP_XOR_MULT_DOSStub_c0c0 {
  strings:
    $key_c0c0 = { 94 a8 [2] e0 b0 [2] a7 b2 [2] e0 a3 [2] ae af [2] a2 a5 [2] b5 ae [2] ae e0 [2] 93 }

  condition:
    any of them
}