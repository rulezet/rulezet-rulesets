rule TTP_XOR_MULT_DOSStub_c12a {
  strings:
    $key_c12a = { 95 42 [2] e1 5a [2] a6 58 [2] e1 49 [2] af 45 [2] a3 4f [2] b4 44 [2] af 0a [2] 92 }

  condition:
    any of them
}