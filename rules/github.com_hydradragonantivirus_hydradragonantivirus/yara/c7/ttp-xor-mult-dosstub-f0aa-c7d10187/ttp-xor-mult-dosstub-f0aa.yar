rule TTP_XOR_MULT_DOSStub_f0aa {
  strings:
    $key_f0aa = { a4 c2 [2] d0 da [2] 97 d8 [2] d0 c9 [2] 9e c5 [2] 92 cf [2] 85 c4 [2] 9e 8a [2] a3 }

  condition:
    any of them
}