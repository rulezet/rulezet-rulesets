rule TTP_XOR_MULT_DOSStub_e7e5 {
  strings:
    $key_e7e5 = { b3 8d [2] c7 95 [2] 80 97 [2] c7 86 [2] 89 8a [2] 85 80 [2] 92 8b [2] 89 c5 [2] b4 }

  condition:
    any of them
}