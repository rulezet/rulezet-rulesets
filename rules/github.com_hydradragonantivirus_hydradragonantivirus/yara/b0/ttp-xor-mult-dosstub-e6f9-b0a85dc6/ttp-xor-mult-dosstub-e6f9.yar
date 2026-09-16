rule TTP_XOR_MULT_DOSStub_e6f9 {
  strings:
    $key_e6f9 = { b2 91 [2] c6 89 [2] 81 8b [2] c6 9a [2] 88 96 [2] 84 9c [2] 93 97 [2] 88 d9 [2] b5 }

  condition:
    any of them
}