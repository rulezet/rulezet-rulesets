rule TTP_XOR_MULT_DOSStub_e0e5 {
  strings:
    $key_e0e5 = { b4 8d [2] c0 95 [2] 87 97 [2] c0 86 [2] 8e 8a [2] 82 80 [2] 95 8b [2] 8e c5 [2] b3 }

  condition:
    any of them
}