rule TTP_XOR_MULT_DOSStub_e1e3 {
  strings:
    $key_e1e3 = { b5 8b [2] c1 93 [2] 86 91 [2] c1 80 [2] 8f 8c [2] 83 86 [2] 94 8d [2] 8f c3 [2] b2 }

  condition:
    any of them
}