rule TTP_XOR_MULT_DOSStub_f68d {
  strings:
    $key_f68d = { a2 e5 [2] d6 fd [2] 91 ff [2] d6 ee [2] 98 e2 [2] 94 e8 [2] 83 e3 [2] 98 ad [2] a5 }

  condition:
    any of them
}