rule TTP_XOR_MULT_DOSStub_e450 {
  strings:
    $key_e450 = { b0 38 [2] c4 20 [2] 83 22 [2] c4 33 [2] 8a 3f [2] 86 35 [2] 91 3e [2] 8a 70 [2] b7 }

  condition:
    any of them
}