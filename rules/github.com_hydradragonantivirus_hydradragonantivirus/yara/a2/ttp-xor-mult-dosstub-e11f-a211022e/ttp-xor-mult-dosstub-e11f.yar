rule TTP_XOR_MULT_DOSStub_e11f {
  strings:
    $key_e11f = { b5 77 [2] c1 6f [2] 86 6d [2] c1 7c [2] 8f 70 [2] 83 7a [2] 94 71 [2] 8f 3f [2] b2 }

  condition:
    any of them
}