rule TTP_XOR_MULT_DOSStub_c451 {
  strings:
    $key_c451 = { 90 39 [2] e4 21 [2] a3 23 [2] e4 32 [2] aa 3e [2] a6 34 [2] b1 3f [2] aa 71 [2] 97 }

  condition:
    any of them
}