rule TTP_XOR_MULT_DOSStub_e0f4 {
  strings:
    $key_e0f4 = { b4 9c [2] c0 84 [2] 87 86 [2] c0 97 [2] 8e 9b [2] 82 91 [2] 95 9a [2] 8e d4 [2] b3 }

  condition:
    any of them
}