rule TTP_XOR_MULT_DOSStub_b7fa {
  strings:
    $key_b7fa = { e3 92 [2] 97 8a [2] d0 88 [2] 97 99 [2] d9 95 [2] d5 9f [2] c2 94 [2] d9 da [2] e4 }

  condition:
    any of them
}