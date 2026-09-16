rule TTP_XOR_MULT_DOSStub_e500 {
  strings:
    $key_e500 = { b1 68 [2] c5 70 [2] 82 72 [2] c5 63 [2] 8b 6f [2] 87 65 [2] 90 6e [2] 8b 20 [2] b6 }

  condition:
    any of them
}