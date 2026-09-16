rule TTP_XOR_MULT_DOSStub_c76a {
  strings:
    $key_c76a = { 93 02 [2] e7 1a [2] a0 18 [2] e7 09 [2] a9 05 [2] a5 0f [2] b2 04 [2] a9 4a [2] 94 }

  condition:
    any of them
}