rule TTP_XOR_MULT_DOSStub_e477 {
  strings:
    $key_e477 = { b0 1f [2] c4 07 [2] 83 05 [2] c4 14 [2] 8a 18 [2] 86 12 [2] 91 19 [2] 8a 57 [2] b7 }

  condition:
    any of them
}