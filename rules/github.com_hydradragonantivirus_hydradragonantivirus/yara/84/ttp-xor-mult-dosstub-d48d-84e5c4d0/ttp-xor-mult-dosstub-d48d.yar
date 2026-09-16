rule TTP_XOR_MULT_DOSStub_d48d {
  strings:
    $key_d48d = { 80 e5 [2] f4 fd [2] b3 ff [2] f4 ee [2] ba e2 [2] b6 e8 [2] a1 e3 [2] ba ad [2] 87 }

  condition:
    any of them
}