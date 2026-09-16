rule TTP_XOR_MULT_DOSStub_c683 {
  strings:
    $key_c683 = { 92 eb [2] e6 f3 [2] a1 f1 [2] e6 e0 [2] a8 ec [2] a4 e6 [2] b3 ed [2] a8 a3 [2] 95 }

  condition:
    any of them
}