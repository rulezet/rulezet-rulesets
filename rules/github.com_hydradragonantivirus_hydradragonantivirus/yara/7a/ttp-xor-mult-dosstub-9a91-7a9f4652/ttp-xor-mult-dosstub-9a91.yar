rule TTP_XOR_MULT_DOSStub_9a91 {
  strings:
    $key_9a91 = { ce f9 [2] ba e1 [2] fd e3 [2] ba f2 [2] f4 fe [2] f8 f4 [2] ef ff [2] f4 b1 [2] c9 }

  condition:
    any of them
}