rule TTP_XOR_MULT_DOSStub_cad3 {
  strings:
    $key_cad3 = { 9e bb [2] ea a3 [2] ad a1 [2] ea b0 [2] a4 bc [2] a8 b6 [2] bf bd [2] a4 f3 [2] 99 }

  condition:
    any of them
}