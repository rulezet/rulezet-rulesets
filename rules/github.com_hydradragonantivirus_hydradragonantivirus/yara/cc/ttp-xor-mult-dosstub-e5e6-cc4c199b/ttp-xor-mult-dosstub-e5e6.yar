rule TTP_XOR_MULT_DOSStub_e5e6 {
  strings:
    $key_e5e6 = { b1 8e [2] c5 96 [2] 82 94 [2] c5 85 [2] 8b 89 [2] 87 83 [2] 90 88 [2] 8b c6 [2] b6 }

  condition:
    any of them
}