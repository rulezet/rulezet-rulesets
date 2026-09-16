rule TTP_XOR_MULT_DOSStub_c62f {
  strings:
    $key_c62f = { 92 47 [2] e6 5f [2] a1 5d [2] e6 4c [2] a8 40 [2] a4 4a [2] b3 41 [2] a8 0f [2] 95 }

  condition:
    any of them
}