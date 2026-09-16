rule TTP_XOR_MULT_DOSStub_b76f {
  strings:
    $key_b76f = { e3 07 [2] 97 1f [2] d0 1d [2] 97 0c [2] d9 00 [2] d5 0a [2] c2 01 [2] d9 4f [2] e4 }

  condition:
    any of them
}