rule TTP_XOR_MULT_DOSStub_6a91 {
  strings:
    $key_6a91 = { 3e f9 [2] 4a e1 [2] 0d e3 [2] 4a f2 [2] 04 fe [2] 08 f4 [2] 1f ff [2] 04 b1 [2] 39 }

  condition:
    any of them
}