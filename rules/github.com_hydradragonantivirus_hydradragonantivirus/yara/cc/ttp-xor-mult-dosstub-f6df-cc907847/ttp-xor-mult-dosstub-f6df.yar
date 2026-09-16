rule TTP_XOR_MULT_DOSStub_f6df {
  strings:
    $key_f6df = { a2 b7 [2] d6 af [2] 91 ad [2] d6 bc [2] 98 b0 [2] 94 ba [2] 83 b1 [2] 98 ff [2] a5 }

  condition:
    any of them
}