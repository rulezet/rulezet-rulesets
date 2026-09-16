rule TTP_XOR_MULT_DOSStub_cc84 {
  strings:
    $key_cc84 = { 98 ec [2] ec f4 [2] ab f6 [2] ec e7 [2] a2 eb [2] ae e1 [2] b9 ea [2] a2 a4 [2] 9f }

  condition:
    any of them
}