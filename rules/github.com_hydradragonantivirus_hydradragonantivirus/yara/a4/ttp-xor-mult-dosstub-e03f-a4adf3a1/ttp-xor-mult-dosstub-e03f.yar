rule TTP_XOR_MULT_DOSStub_e03f {
  strings:
    $key_e03f = { b4 57 [2] c0 4f [2] 87 4d [2] c0 5c [2] 8e 50 [2] 82 5a [2] 95 51 [2] 8e 1f [2] b3 }

  condition:
    any of them
}