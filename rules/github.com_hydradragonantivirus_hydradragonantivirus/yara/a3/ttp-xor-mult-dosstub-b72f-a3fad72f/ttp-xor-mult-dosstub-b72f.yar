rule TTP_XOR_MULT_DOSStub_b72f {
  strings:
    $key_b72f = { e3 47 [2] 97 5f [2] d0 5d [2] 97 4c [2] d9 40 [2] d5 4a [2] c2 41 [2] d9 0f [2] e4 }

  condition:
    any of them
}