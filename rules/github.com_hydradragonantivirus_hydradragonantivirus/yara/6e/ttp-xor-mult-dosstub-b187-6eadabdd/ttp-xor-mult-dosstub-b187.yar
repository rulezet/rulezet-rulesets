rule TTP_XOR_MULT_DOSStub_b187 {
  strings:
    $key_b187 = { e5 ef [2] 91 f7 [2] d6 f5 [2] 91 e4 [2] df e8 [2] d3 e2 [2] c4 e9 [2] df a7 [2] e2 }

  condition:
    any of them
}