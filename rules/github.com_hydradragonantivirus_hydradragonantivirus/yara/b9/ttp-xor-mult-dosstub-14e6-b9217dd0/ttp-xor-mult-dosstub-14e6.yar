rule TTP_XOR_MULT_DOSStub_14e6 {
  strings:
    $key_14e6 = { 40 8e [2] 34 96 [2] 73 94 [2] 34 85 [2] 7a 89 [2] 76 83 [2] 61 88 [2] 7a c6 [2] 47 }

  condition:
    any of them
}