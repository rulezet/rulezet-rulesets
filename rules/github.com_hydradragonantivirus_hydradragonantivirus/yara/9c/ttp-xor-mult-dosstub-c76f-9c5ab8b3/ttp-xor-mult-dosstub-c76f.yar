rule TTP_XOR_MULT_DOSStub_c76f {
  strings:
    $key_c76f = { 93 07 [2] e7 1f [2] a0 1d [2] e7 0c [2] a9 00 [2] a5 0a [2] b2 01 [2] a9 4f [2] 94 }

  condition:
    any of them
}