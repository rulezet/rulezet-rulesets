rule TTP_XOR_MULT_DOSStub_c384 {
  strings:
    $key_c384 = { 97 ec [2] e3 f4 [2] a4 f6 [2] e3 e7 [2] ad eb [2] a1 e1 [2] b6 ea [2] ad a4 [2] 90 }

  condition:
    any of them
}