rule TTP_XOR_MULT_DOSStub_c45b {
  strings:
    $key_c45b = { 90 33 [2] e4 2b [2] a3 29 [2] e4 38 [2] aa 34 [2] a6 3e [2] b1 35 [2] aa 7b [2] 97 }

  condition:
    any of them
}