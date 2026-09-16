rule TTP_XOR_MULT_DOSStub_e08d {
  strings:
    $key_e08d = { b4 e5 [2] c0 fd [2] 87 ff [2] c0 ee [2] 8e e2 [2] 82 e8 [2] 95 e3 [2] 8e ad [2] b3 }

  condition:
    any of them
}