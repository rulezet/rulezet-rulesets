rule TTP_XOR_MULT_DOSStub_f3cc {
  strings:
    $key_f3cc = { a7 a4 [2] d3 bc [2] 94 be [2] d3 af [2] 9d a3 [2] 91 a9 [2] 86 a2 [2] 9d ec [2] a0 }

  condition:
    any of them
}