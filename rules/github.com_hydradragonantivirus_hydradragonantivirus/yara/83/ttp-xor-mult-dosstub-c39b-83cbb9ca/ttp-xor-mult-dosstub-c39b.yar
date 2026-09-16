rule TTP_XOR_MULT_DOSStub_c39b {
  strings:
    $key_c39b = { 97 f3 [2] e3 eb [2] a4 e9 [2] e3 f8 [2] ad f4 [2] a1 fe [2] b6 f5 [2] ad bb [2] 90 }

  condition:
    any of them
}