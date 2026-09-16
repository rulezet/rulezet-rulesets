rule TTP_XOR_MULT_DOSStub_cc85 {
  strings:
    $key_cc85 = { 98 ed [2] ec f5 [2] ab f7 [2] ec e6 [2] a2 ea [2] ae e0 [2] b9 eb [2] a2 a5 [2] 9f }

  condition:
    any of them
}