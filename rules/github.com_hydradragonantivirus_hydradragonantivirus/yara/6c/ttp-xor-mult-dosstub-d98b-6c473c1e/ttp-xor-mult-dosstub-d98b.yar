rule TTP_XOR_MULT_DOSStub_d98b {
  strings:
    $key_d98b = { 8d e3 [2] f9 fb [2] be f9 [2] f9 e8 [2] b7 e4 [2] bb ee [2] ac e5 [2] b7 ab [2] 8a }

  condition:
    any of them
}