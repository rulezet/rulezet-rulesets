rule TTP_XOR_MULT_DOSStub_c32a {
  strings:
    $key_c32a = { 97 42 [2] e3 5a [2] a4 58 [2] e3 49 [2] ad 45 [2] a1 4f [2] b6 44 [2] ad 0a [2] 90 }

  condition:
    any of them
}