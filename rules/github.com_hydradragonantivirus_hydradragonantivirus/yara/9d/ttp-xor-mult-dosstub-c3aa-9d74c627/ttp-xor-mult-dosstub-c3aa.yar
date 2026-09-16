rule TTP_XOR_MULT_DOSStub_c3aa {
  strings:
    $key_c3aa = { 97 c2 [2] e3 da [2] a4 d8 [2] e3 c9 [2] ad c5 [2] a1 cf [2] b6 c4 [2] ad 8a [2] 90 }

  condition:
    any of them
}