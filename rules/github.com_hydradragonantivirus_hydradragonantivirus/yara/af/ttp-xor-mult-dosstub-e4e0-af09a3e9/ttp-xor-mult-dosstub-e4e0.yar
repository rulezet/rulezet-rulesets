rule TTP_XOR_MULT_DOSStub_e4e0 {
  strings:
    $key_e4e0 = { b0 88 [2] c4 90 [2] 83 92 [2] c4 83 [2] 8a 8f [2] 86 85 [2] 91 8e [2] 8a c0 [2] b7 }

  condition:
    any of them
}