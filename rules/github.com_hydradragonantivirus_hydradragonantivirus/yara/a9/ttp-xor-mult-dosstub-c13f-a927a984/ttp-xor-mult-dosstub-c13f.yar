rule TTP_XOR_MULT_DOSStub_c13f {
  strings:
    $key_c13f = { 95 57 [2] e1 4f [2] a6 4d [2] e1 5c [2] af 50 [2] a3 5a [2] b4 51 [2] af 1f [2] 92 }

  condition:
    any of them
}