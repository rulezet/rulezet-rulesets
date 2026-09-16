rule TTP_XOR_MULT_DOSStub_04e1 {
  strings:
    $key_04e1 = { 50 89 [2] 24 91 [2] 63 93 [2] 24 82 [2] 6a 8e [2] 66 84 [2] 71 8f [2] 6a c1 [2] 57 }

  condition:
    any of them
}