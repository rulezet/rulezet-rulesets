rule TTP_XOR_MULT_DOSStub_e05a {
  strings:
    $key_e05a = { b4 32 [2] c0 2a [2] 87 28 [2] c0 39 [2] 8e 35 [2] 82 3f [2] 95 34 [2] 8e 7a [2] b3 }

  condition:
    any of them
}