rule TTP_XOR_MULT_DOSStub_c383 {
  strings:
    $key_c383 = { 97 eb [2] e3 f3 [2] a4 f1 [2] e3 e0 [2] ad ec [2] a1 e6 [2] b6 ed [2] ad a3 [2] 90 }

  condition:
    any of them
}