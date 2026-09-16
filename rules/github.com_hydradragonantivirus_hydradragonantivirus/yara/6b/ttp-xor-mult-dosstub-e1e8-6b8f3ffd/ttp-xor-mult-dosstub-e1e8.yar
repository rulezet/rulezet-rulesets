rule TTP_XOR_MULT_DOSStub_e1e8 {
  strings:
    $key_e1e8 = { b5 80 [2] c1 98 [2] 86 9a [2] c1 8b [2] 8f 87 [2] 83 8d [2] 94 86 [2] 8f c8 [2] b2 }

  condition:
    any of them
}