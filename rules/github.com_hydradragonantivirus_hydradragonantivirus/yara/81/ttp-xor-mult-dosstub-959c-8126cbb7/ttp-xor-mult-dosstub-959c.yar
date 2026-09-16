rule TTP_XOR_MULT_DOSStub_959c {
  strings:
    $key_959c = { c1 f4 [2] b5 ec [2] f2 ee [2] b5 ff [2] fb f3 [2] f7 f9 [2] e0 f2 [2] fb bc [2] c6 }

  condition:
    any of them
}