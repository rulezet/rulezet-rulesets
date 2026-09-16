rule TTP_XOR_MULT_DOSStub_5a91 {
  strings:
    $key_5a91 = { 0e f9 [2] 7a e1 [2] 3d e3 [2] 7a f2 [2] 34 fe [2] 38 f4 [2] 2f ff [2] 34 b1 [2] 09 }

  condition:
    any of them
}