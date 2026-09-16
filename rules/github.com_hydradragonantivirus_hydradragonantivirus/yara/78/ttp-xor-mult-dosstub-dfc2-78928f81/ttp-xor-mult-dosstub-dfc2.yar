rule TTP_XOR_MULT_DOSStub_dfc2 {
  strings:
    $key_dfc2 = { 8b aa [2] ff b2 [2] b8 b0 [2] ff a1 [2] b1 ad [2] bd a7 [2] aa ac [2] b1 e2 [2] 8c }

  condition:
    any of them
}