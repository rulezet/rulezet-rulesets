rule TTP_XOR_MULT_DOSStub_f5df {
  strings:
    $key_f5df = { a1 b7 [2] d5 af [2] 92 ad [2] d5 bc [2] 9b b0 [2] 97 ba [2] 80 b1 [2] 9b ff [2] a6 }

  condition:
    any of them
}