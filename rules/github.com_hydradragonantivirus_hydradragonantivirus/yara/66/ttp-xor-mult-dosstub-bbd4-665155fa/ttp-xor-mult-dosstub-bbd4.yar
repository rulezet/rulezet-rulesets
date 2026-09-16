rule TTP_XOR_MULT_DOSStub_bbd4 {
  strings:
    $key_bbd4 = { ef bc [2] 9b a4 [2] dc a6 [2] 9b b7 [2] d5 bb [2] d9 b1 [2] ce ba [2] d5 f4 [2] e8 }

  condition:
    any of them
}