rule TTP_XOR_MULT_DOSStub_c03a {
  strings:
    $key_c03a = { 94 52 [2] e0 4a [2] a7 48 [2] e0 59 [2] ae 55 [2] a2 5f [2] b5 54 [2] ae 1a [2] 93 }

  condition:
    any of them
}