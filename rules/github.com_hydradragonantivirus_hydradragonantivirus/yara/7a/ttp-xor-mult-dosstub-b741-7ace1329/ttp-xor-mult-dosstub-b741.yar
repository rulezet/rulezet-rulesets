rule TTP_XOR_MULT_DOSStub_b741 {
  strings:
    $key_b741 = { e3 29 [2] 97 31 [2] d0 33 [2] 97 22 [2] d9 2e [2] d5 24 [2] c2 2f [2] d9 61 [2] e4 }

  condition:
    any of them
}