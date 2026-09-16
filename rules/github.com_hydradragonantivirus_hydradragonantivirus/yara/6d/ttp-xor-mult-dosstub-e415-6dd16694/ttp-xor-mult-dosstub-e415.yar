rule TTP_XOR_MULT_DOSStub_e415 {
  strings:
    $key_e415 = { b0 7d [2] c4 65 [2] 83 67 [2] c4 76 [2] 8a 7a [2] 86 70 [2] 91 7b [2] 8a 35 [2] b7 }

  condition:
    any of them
}