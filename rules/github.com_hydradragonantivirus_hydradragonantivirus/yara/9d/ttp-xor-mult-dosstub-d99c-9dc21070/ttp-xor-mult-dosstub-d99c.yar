rule TTP_XOR_MULT_DOSStub_d99c {
  strings:
    $key_d99c = { 8d f4 [2] f9 ec [2] be ee [2] f9 ff [2] b7 f3 [2] bb f9 [2] ac f2 [2] b7 bc [2] 8a }

  condition:
    any of them
}