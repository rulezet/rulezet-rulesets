rule TTP_XOR_MULT_DOSStub_e400 {
  strings:
    $key_e400 = { b0 68 [2] c4 70 [2] 83 72 [2] c4 63 [2] 8a 6f [2] 86 65 [2] 91 6e [2] 8a 20 [2] b7 }

  condition:
    any of them
}