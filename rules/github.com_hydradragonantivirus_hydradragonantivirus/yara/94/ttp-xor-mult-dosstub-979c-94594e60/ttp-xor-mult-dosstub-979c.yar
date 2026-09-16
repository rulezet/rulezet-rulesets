rule TTP_XOR_MULT_DOSStub_979c {
  strings:
    $key_979c = { c3 f4 [2] b7 ec [2] f0 ee [2] b7 ff [2] f9 f3 [2] f5 f9 [2] e2 f2 [2] f9 bc [2] c4 }

  condition:
    any of them
}