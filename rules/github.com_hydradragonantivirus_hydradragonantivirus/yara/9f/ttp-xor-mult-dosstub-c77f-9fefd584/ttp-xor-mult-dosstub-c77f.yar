rule TTP_XOR_MULT_DOSStub_c77f {
  strings:
    $key_c77f = { 93 17 [2] e7 0f [2] a0 0d [2] e7 1c [2] a9 10 [2] a5 1a [2] b2 11 [2] a9 5f [2] 94 }

  condition:
    any of them
}