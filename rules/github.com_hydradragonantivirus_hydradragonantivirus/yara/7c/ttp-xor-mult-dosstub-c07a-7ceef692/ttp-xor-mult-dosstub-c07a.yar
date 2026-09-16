rule TTP_XOR_MULT_DOSStub_c07a {
  strings:
    $key_c07a = { 94 12 [2] e0 0a [2] a7 08 [2] e0 19 [2] ae 15 [2] a2 1f [2] b5 14 [2] ae 5a [2] 93 }

  condition:
    any of them
}