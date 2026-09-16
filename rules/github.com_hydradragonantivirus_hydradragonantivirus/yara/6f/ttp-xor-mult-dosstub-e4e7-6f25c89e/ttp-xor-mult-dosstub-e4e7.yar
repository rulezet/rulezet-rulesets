rule TTP_XOR_MULT_DOSStub_e4e7 {
  strings:
    $key_e4e7 = { b0 8f [2] c4 97 [2] 83 95 [2] c4 84 [2] 8a 88 [2] 86 82 [2] 91 89 [2] 8a c7 [2] b7 }

  condition:
    any of them
}