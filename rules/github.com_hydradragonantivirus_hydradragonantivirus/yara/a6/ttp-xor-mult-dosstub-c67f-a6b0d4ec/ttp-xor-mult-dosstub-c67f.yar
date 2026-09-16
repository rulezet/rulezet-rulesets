rule TTP_XOR_MULT_DOSStub_c67f {
  strings:
    $key_c67f = { 92 17 [2] e6 0f [2] a1 0d [2] e6 1c [2] a8 10 [2] a4 1a [2] b3 11 [2] a8 5f [2] 95 }

  condition:
    any of them
}