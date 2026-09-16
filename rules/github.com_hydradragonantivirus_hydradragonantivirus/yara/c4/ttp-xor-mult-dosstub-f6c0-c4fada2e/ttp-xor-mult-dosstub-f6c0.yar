rule TTP_XOR_MULT_DOSStub_f6c0 {
  strings:
    $key_f6c0 = { a2 a8 [2] d6 b0 [2] 91 b2 [2] d6 a3 [2] 98 af [2] 94 a5 [2] 83 ae [2] 98 e0 [2] a5 }

  condition:
    any of them
}