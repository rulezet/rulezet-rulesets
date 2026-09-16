rule TTP_XOR_MULT_DOSStub_c10f {
  strings:
    $key_c10f = { 95 67 [2] e1 7f [2] a6 7d [2] e1 6c [2] af 60 [2] a3 6a [2] b4 61 [2] af 2f [2] 92 }

  condition:
    any of them
}