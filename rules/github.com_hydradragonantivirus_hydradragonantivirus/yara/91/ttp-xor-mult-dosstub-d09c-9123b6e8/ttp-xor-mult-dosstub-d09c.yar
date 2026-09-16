rule TTP_XOR_MULT_DOSStub_d09c {
  strings:
    $key_d09c = { 84 f4 [2] f0 ec [2] b7 ee [2] f0 ff [2] be f3 [2] b2 f9 [2] a5 f2 [2] be bc [2] 83 }

  condition:
    any of them
}