rule TTP_XOR_MULT_DOSStub_dfc1 {
  strings:
    $key_dfc1 = { 8b a9 [2] ff b1 [2] b8 b3 [2] ff a2 [2] b1 ae [2] bd a4 [2] aa af [2] b1 e1 [2] 8c }

  condition:
    any of them
}