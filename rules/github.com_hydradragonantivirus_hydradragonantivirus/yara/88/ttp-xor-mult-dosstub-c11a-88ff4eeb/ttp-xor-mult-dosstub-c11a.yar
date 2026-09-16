rule TTP_XOR_MULT_DOSStub_c11a {
  strings:
    $key_c11a = { 95 72 [2] e1 6a [2] a6 68 [2] e1 79 [2] af 75 [2] a3 7f [2] b4 74 [2] af 3a [2] 92 }

  condition:
    any of them
}