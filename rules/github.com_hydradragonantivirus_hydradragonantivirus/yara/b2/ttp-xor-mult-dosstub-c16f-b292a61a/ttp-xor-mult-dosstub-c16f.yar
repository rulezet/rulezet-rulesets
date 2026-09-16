rule TTP_XOR_MULT_DOSStub_c16f {
  strings:
    $key_c16f = { 95 07 [2] e1 1f [2] a6 1d [2] e1 0c [2] af 00 [2] a3 0a [2] b4 01 [2] af 4f [2] 92 }

  condition:
    any of them
}