rule TTP_XOR_MULT_DOSStub_7a91 {
  strings:
    $key_7a91 = { 2e f9 [2] 5a e1 [2] 1d e3 [2] 5a f2 [2] 14 fe [2] 18 f4 [2] 0f ff [2] 14 b1 [2] 29 }

  condition:
    any of them
}