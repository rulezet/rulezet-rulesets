rule TTP_XOR_MULT_DOSStub_14e0 {
  strings:
    $key_14e0 = { 40 88 [2] 34 90 [2] 73 92 [2] 34 83 [2] 7a 8f [2] 76 85 [2] 61 8e [2] 7a c0 [2] 47 }

  condition:
    any of them
}