rule TTP_XOR_MULT_DOSStub_e13f {
  strings:
    $key_e13f = { b5 57 [2] c1 4f [2] 86 4d [2] c1 5c [2] 8f 50 [2] 83 5a [2] 94 51 [2] 8f 1f [2] b2 }

  condition:
    any of them
}