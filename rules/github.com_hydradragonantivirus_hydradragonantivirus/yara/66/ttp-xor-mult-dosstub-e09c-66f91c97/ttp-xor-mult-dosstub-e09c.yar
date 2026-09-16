rule TTP_XOR_MULT_DOSStub_e09c {
  strings:
    $key_e09c = { b4 f4 [2] c0 ec [2] 87 ee [2] c0 ff [2] 8e f3 [2] 82 f9 [2] 95 f2 [2] 8e bc [2] b3 }

  condition:
    any of them
}