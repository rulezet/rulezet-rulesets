rule TTP_XOR_MULT_DOSStub_c15f {
  strings:
    $key_c15f = { 95 37 [2] e1 2f [2] a6 2d [2] e1 3c [2] af 30 [2] a3 3a [2] b4 31 [2] af 7f [2] 92 }

  condition:
    any of them
}