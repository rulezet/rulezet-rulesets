rule TTP_XOR_MULT_DOSStub_c59b {
  strings:
    $key_c59b = { 91 f3 [2] e5 eb [2] a2 e9 [2] e5 f8 [2] ab f4 [2] a7 fe [2] b0 f5 [2] ab bb [2] 96 }

  condition:
    any of them
}