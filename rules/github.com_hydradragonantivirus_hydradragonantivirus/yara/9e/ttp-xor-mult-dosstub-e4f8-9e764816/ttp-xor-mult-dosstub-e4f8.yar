rule TTP_XOR_MULT_DOSStub_e4f8 {
  strings:
    $key_e4f8 = { b0 90 [2] c4 88 [2] 83 8a [2] c4 9b [2] 8a 97 [2] 86 9d [2] 91 96 [2] 8a d8 [2] b7 }

  condition:
    any of them
}