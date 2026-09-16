rule TTP_XOR_MULT_DOSStub_e7f9 {
  strings:
    $key_e7f9 = { b3 91 [2] c7 89 [2] 80 8b [2] c7 9a [2] 89 96 [2] 85 9c [2] 92 97 [2] 89 d9 [2] b4 }

  condition:
    any of them
}