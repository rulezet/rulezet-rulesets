rule TTP_XOR_MULT_DOSStub_b77f {
  strings:
    $key_b77f = { e3 17 [2] 97 0f [2] d0 0d [2] 97 1c [2] d9 10 [2] d5 1a [2] c2 11 [2] d9 5f [2] e4 }

  condition:
    any of them
}