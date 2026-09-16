rule TTP_XOR_MULT_DOSStub_e43f {
  strings:
    $key_e43f = { b0 57 [2] c4 4f [2] 83 4d [2] c4 5c [2] 8a 50 [2] 86 5a [2] 91 51 [2] 8a 1f [2] b7 }

  condition:
    any of them
}