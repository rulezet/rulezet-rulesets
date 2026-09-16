rule TTP_XOR_MULT_DOSStub_dd8b {
  strings:
    $key_dd8b = { 89 e3 [2] fd fb [2] ba f9 [2] fd e8 [2] b3 e4 [2] bf ee [2] a8 e5 [2] b3 ab [2] 8e }

  condition:
    any of them
}