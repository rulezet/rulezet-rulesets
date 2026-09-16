rule TTP_XOR_MULT_DOSStub_e5f9 {
  strings:
    $key_e5f9 = { b1 91 [2] c5 89 [2] 82 8b [2] c5 9a [2] 8b 96 [2] 87 9c [2] 90 97 [2] 8b d9 [2] b6 }

  condition:
    any of them
}