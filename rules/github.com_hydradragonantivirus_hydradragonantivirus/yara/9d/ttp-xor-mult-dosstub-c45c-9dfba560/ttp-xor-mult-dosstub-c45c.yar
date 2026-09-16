rule TTP_XOR_MULT_DOSStub_c45c {
  strings:
    $key_c45c = { 90 34 [2] e4 2c [2] a3 2e [2] e4 3f [2] aa 33 [2] a6 39 [2] b1 32 [2] aa 7c [2] 97 }

  condition:
    any of them
}