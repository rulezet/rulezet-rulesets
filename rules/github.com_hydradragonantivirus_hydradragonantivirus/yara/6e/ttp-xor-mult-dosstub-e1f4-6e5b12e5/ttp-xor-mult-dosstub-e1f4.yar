rule TTP_XOR_MULT_DOSStub_e1f4 {
  strings:
    $key_e1f4 = { b5 9c [2] c1 84 [2] 86 86 [2] c1 97 [2] 8f 9b [2] 83 91 [2] 94 9a [2] 8f d4 [2] b2 }

  condition:
    any of them
}