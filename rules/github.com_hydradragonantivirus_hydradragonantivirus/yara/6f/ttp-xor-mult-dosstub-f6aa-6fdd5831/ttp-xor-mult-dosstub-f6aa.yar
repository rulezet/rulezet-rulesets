rule TTP_XOR_MULT_DOSStub_f6aa {
  strings:
    $key_f6aa = { a2 c2 [2] d6 da [2] 91 d8 [2] d6 c9 [2] 98 c5 [2] 94 cf [2] 83 c4 [2] 98 8a [2] a5 }

  condition:
    any of them
}