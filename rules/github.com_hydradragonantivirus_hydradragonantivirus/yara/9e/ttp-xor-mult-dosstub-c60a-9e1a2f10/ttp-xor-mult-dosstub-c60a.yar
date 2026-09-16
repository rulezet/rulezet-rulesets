rule TTP_XOR_MULT_DOSStub_c60a {
  strings:
    $key_c60a = { 92 62 [2] e6 7a [2] a1 78 [2] e6 69 [2] a8 65 [2] a4 6f [2] b3 64 [2] a8 2a [2] 95 }

  condition:
    any of them
}