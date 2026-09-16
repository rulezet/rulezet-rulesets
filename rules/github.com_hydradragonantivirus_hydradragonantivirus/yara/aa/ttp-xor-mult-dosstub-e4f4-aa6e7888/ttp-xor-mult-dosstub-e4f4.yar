rule TTP_XOR_MULT_DOSStub_e4f4 {
  strings:
    $key_e4f4 = { b0 9c [2] c4 84 [2] 83 86 [2] c4 97 [2] 8a 9b [2] 86 91 [2] 91 9a [2] 8a d4 [2] b7 }

  condition:
    any of them
}