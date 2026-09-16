rule TTP_XOR_MULT_DOSStub_b18b {
  strings:
    $key_b18b = { e5 e3 [2] 91 fb [2] d6 f9 [2] 91 e8 [2] df e4 [2] d3 ee [2] c4 e5 [2] df ab [2] e2 }

  condition:
    any of them
}