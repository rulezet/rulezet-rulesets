rule TTP_XOR_MULT_DOSStub_e1f9 {
  strings:
    $key_e1f9 = { b5 91 [2] c1 89 [2] 86 8b [2] c1 9a [2] 8f 96 [2] 83 9c [2] 94 97 [2] 8f d9 [2] b2 }

  condition:
    any of them
}