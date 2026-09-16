rule TTP_XOR_MULT_DOSStub_24c0 {
  strings:
    $key_24c0 = { 70 a8 [2] 04 b0 [2] 43 b2 [2] 04 a3 [2] 4a af [2] 46 a5 [2] 51 ae [2] 4a e0 [2] 77 }

  condition:
    any of them
}