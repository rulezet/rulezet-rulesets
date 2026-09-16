rule TTP_XOR_MULT_DOSStub_f69c {
  strings:
    $key_f69c = { a2 f4 [2] d6 ec [2] 91 ee [2] d6 ff [2] 98 f3 [2] 94 f9 [2] 83 f2 [2] 98 bc [2] a5 }

  condition:
    any of them
}