rule TTP_XOR_MULT_DOSStub_0a91 {
  strings:
    $key_0a91 = { 5e f9 [2] 2a e1 [2] 6d e3 [2] 2a f2 [2] 64 fe [2] 68 f4 [2] 7f ff [2] 64 b1 [2] 59 }

  condition:
    any of them
}