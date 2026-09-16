rule TTP_XOR_MULT_DOSStub_3a91 {
  strings:
    $key_3a91 = { 6e f9 [2] 1a e1 [2] 5d e3 [2] 1a f2 [2] 54 fe [2] 58 f4 [2] 4f ff [2] 54 b1 [2] 69 }

  condition:
    any of them
}