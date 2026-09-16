rule TTP_XOR_MULT_DOSStub_da98 {
  strings:
    $key_da98 = { 8e f0 [2] fa e8 [2] bd ea [2] fa fb [2] b4 f7 [2] b8 fd [2] af f6 [2] b4 b8 [2] 89 }

  condition:
    any of them
}