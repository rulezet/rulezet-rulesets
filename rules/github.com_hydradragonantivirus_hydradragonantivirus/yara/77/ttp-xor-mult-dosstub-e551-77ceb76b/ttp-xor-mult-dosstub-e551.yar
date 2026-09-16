rule TTP_XOR_MULT_DOSStub_e551 {
  strings:
    $key_e551 = { b1 39 [2] c5 21 [2] 82 23 [2] c5 32 [2] 8b 3e [2] 87 34 [2] 90 3f [2] 8b 71 [2] b6 }

  condition:
    any of them
}