rule TTP_XOR_MULT_DOSStub_dfc8 {
  strings:
    $key_dfc8 = { 8b a0 [2] ff b8 [2] b8 ba [2] ff ab [2] b1 a7 [2] bd ad [2] aa a6 [2] b1 e8 [2] 8c }

  condition:
    any of them
}