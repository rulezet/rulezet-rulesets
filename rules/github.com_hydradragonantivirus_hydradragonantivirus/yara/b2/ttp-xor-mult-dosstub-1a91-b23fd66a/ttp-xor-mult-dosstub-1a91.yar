rule TTP_XOR_MULT_DOSStub_1a91 {
  strings:
    $key_1a91 = { 4e f9 [2] 3a e1 [2] 7d e3 [2] 3a f2 [2] 74 fe [2] 78 f4 [2] 6f ff [2] 74 b1 [2] 49 }

  condition:
    any of them
}