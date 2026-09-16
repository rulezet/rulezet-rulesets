rule TTP_XOR_MULT_DOSStub_e1e5 {
  strings:
    $key_e1e5 = { b5 8d [2] c1 95 [2] 86 97 [2] c1 86 [2] 8f 8a [2] 83 80 [2] 94 8b [2] 8f c5 [2] b2 }

  condition:
    any of them
}